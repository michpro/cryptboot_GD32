/**
 * @file cryptboot_GD32.ino
 * @brief Secure Bootloader implementation for GD32F30x microcontrollers.
 * This module manages the secure firmware update process, including:
 * - Integrity verification using SHA-256 and GD32-compatible CRC32.
 * - Authenticity verification using ECDSA P-256 digital signatures.
 * - Confidentiality through AES-256-CFB decryption.
 * - Secure jump to application with full peripheral cleanup.
 * 
 * @copyright SPDX-FileCopyrightText: Copyright 2025-2026 by Michal Protasowicki
 * @license SPDX-License-Identifier: MIT
 */

#ifndef GD32F30x
#   error Unsupported MCU!!!
#endif

#include <Arduino.h>
#include "src/declarations.h"

// Forward declarations of internal functions
static inline bool isBootloaderRequested(uint32_t causeOfReset);
static inline bool isValidCauseOfReset(uint32_t causeOfReset);
static inline void loadBootloaderData(void);
static inline bool isFirmwareSchouldBeProcessed(void);
static inline bool isFirmwareSignatureOk(void);
static inline bool processFirmwareData(void);
static inline void cleanStoredFirmware(void);
static inline bool isApplicationValid(void);
static inline void jumpToApplication(void);
static void ledBlink(uint_fast8_t count);
static void ledToggle(uint8_t mask);

/**
 * @brief Early initialization constructor.
 * Executed before main() to ensure basic system clock and VTOR are set.
 */
__attribute__((constructor(101))) void premain()
{
    systick_config();

    // Set Vector Table Offset Register to Flash base
    SCB->VTOR = FLASH_BASE;
    __DSB();
}

/**
 * @brief Main entry point of the bootloader.
 * Orchestrates the reset analysis, firmware processing, and application launch.
 */
__attribute__((naked)) int main(void)
{
    u32_u16_union_t causeOfReset;

    // Capture and store reset reason in backup registers for potential app usage
    causeOfReset.u32 = RCU_RSTSCK;
    bkp_write_data(BKP_DATA_0, causeOfReset.u16[0]);
    bkp_write_data(BKP_DATA_1, causeOfReset.u16[1]);

    LED_INIT();
    ledToggle(0x01);

    // Check if a valid firmware update is pending
    if (true == isBootloaderRequested(causeOfReset.u32))
    {
        ledBlink(3);
        if (true == processFirmwareData())
        {
            cleanStoredFirmware();
            ledBlink(6);
        }
    }

    LED_OFF();

    // Validation and jump to the main application
    if (true == isApplicationValid())
    {
        jumpToApplication();
    } 
    else
    {
        // Permanent error state: Application invalid
        LED_ON();
        delay(2000);
        while (true)
        {
            ledBlink(5);
            delay(300);
        }
    }

    return 0;
}

/**
 * @brief Checks if a firmware update process should be initiated.
 * @param causeOfReset The value of the reset status register.
 * @return true if valid firmware metadata and signature are present.
 */
static inline bool isBootloaderRequested(uint32_t causeOfReset)
{
    bool result {false};
    if (true == isValidCauseOfReset(causeOfReset))
    {
        loadBootloaderData();
        result = (isFirmwareSchouldBeProcessed() && isFirmwareSignatureOk());
    }
    return result;
}

/**
 * @brief Validates the reset cause against allowed triggers.
 * @param causeOfReset Reset status register value.
 * @return true if reset was caused by Pin, Power-on, or Software trigger.
 */
static inline bool isValidCauseOfReset(uint32_t causeOfReset)
{
    return (0 != (causeOfReset & (RCU_RSTSCK_EPRSTF | RCU_RSTSCK_PORRSTF | RCU_RSTSCK_SWRSTF)));
}

/**
 * @brief Loads metadata from both internal Flash (pending firmware) and NVStorage (current config).
 */
static inline void loadBootloaderData(void)
{
    Flash::read(FIRMWARE_STORE_BASE_ADDRESS, (uint8_t *)&firmwareConfig, sizeof(firmwareCfg_t));
    NVStorage::init(NV_STORAGE_BASE_ADDRESS);

    memset(bootConfig.key, 0xFF, sizeof(bootConfig));

    NVStorage::read(ID_CIPHER_KEY, bootConfig.key);
    NVStorage::read(ID_FIRMWARE_TIMESTAMP, (uint8_t *)&bootConfig.timeStamp);
    NVStorage::read(ID_FIRMWARE_SIZE, (uint8_t *)&bootConfig.firmwareSize);
    NVStorage::read(ID_FIRMWARE_CRC, (uint8_t *)&bootConfig.firmwareCrc32);
}

/**
 * @brief Verifies firmware metadata version, timestamp (anti-rollback), and size.
 * @return true if firmware is eligible for processing.
 */
static inline bool isFirmwareSchouldBeProcessed(void)
{
    bool result {false};

#if !defined(DOWNGRADE_ALLOWED) | (defined(DOWNGRADE_ALLOWED) && DOWNGRADE_ALLOWED != 1)
    // Anti-rollback logic: Only allow newer timestamps
    if (    (true == MODE_SIG_PARAMS_OK())
        &&  (true == MODE_NEW_KEY_CIPHER_OK())
        &&  (true == MODE_FIRMWARE_CIPHER_OK())
        &&  (BOOTLOADER_DATA_VERSION == firmwareConfig.version)
        &&  ((firmwareConfig.timeStamp > bootConfig.timeStamp) || (0xFFFFFFFF == bootConfig.timeStamp))
        &&  (firmwareConfig.firmwareSize > 0)
        &&  (firmwareConfig.firmwareSize <= APP_MAX_SIZE))
#else
    // Downgrade allowed: Accept any different valid timestamp
    if (    
        (true == MODE_SIG_PARAMS_OK())
        &&  (true == MODE_NEW_KEY_CIPHER_OK())
        &&  (true == MODE_FIRMWARE_CIPHER_OK())
        &&  (BOOTLOADER_DATA_VERSION == firmwareConfig.version)
        &&  (firmwareConfig.timeStamp != 0xFFFFFFFF)
        &&  (firmwareConfig.timeStamp != bootConfig.timeStamp)
        &&  (firmwareConfig.firmwareSize > 0)
        &&  (firmwareConfig.firmwareSize <= APP_MAX_SIZE))
#endif
    {
        result = true;
    }
    return result;
}

/**
 * @brief Verifies the ECDSA P-256 digital signature of the firmware image.
 * Computes SHA-256 hash over:
 * 1. First header chunk (metadata)
 * 2. Second header chunk (IV + encrypted key)
 * 3. Entire firmware payload
 * @return true if the calculated hash matches the signature using the Public Key.
 */
static inline bool isFirmwareSignatureOk(void)
{
    constexpr uint32_t  FIRST_CHUNK_SIZE            {sizeof(firmwareConfig.version)      + sizeof(firmwareConfig.mode) +
                                                     sizeof(firmwareConfig.rfuA)         + sizeof(firmwareConfig.timeStamp) +
                                                     sizeof(firmwareConfig.firmwareSize) + sizeof(firmwareConfig.firmwareCrc32)};
    constexpr uint32_t  SECOND_CHUNK_SIZE           {sizeof(firmwareConfig.cipherIv)     + sizeof(firmwareConfig.newKey)};

    SHA256::context_t   shaCtx;
    uint8_t             hash[SHA256::HASH_SIZE]   = {0};
    uint32_t            startPos                    {0};
    uint32_t            remainingBytes              {firmwareConfig.firmwareSize};
    uint32_t            shift                       {(firmwareConfig.firmwareSize < PAGE_SIZE_BYTE) ?
                                                     firmwareConfig.firmwareSize : PAGE_SIZE_BYTE};
    bool                result                      {false};

    SHA256::init(&shaCtx);
    // Hash header components
    SHA256::update(&shaCtx, (uint8_t *)&firmwareConfig.version, FIRST_CHUNK_SIZE);
    SHA256::update(&shaCtx, (uint8_t *)&firmwareConfig.cipherIv, SECOND_CHUNK_SIZE);

    // Hash firmware payload page-by-page to save RAM
    while (shift)
    {
        Flash::read((APP_STORE_BASE_ADDRESS + startPos), buffer, shift);
        SHA256::update(&shaCtx, buffer, shift);

        startPos += shift;
        remainingBytes = firmwareConfig.firmwareSize - startPos;
        if (remainingBytes < PAGE_SIZE_BYTE)
        {
            shift = remainingBytes;
        }
    }

    SHA256::final(&shaCtx, hash);
    
    // ECDSA Verification against the hardcoded Public Key
    result = (P256::SUCCESS == P256::verify(firmwareConfig.signature, BOOTLOADER_PUBLIC_KEY, hash, SHA256::HASH_SIZE));

    if (false == result)
    {
        // Block replay of invalid firmware by updating stored timestamp
        NVStorage::write(ID_FIRMWARE_TIMESTAMP, (uint8_t *)&firmwareConfig.timeStamp, sizeof(firmwareConfig.timeStamp));
    }

    return result;
}

/**
 * @brief Decrypts and writes firmware to the application partition.
 * Handles AES-256-CFB decryption of both the image and the new cryptographic key distributed within the header.
 * 
 * @return true if all write operations were successful.
 */
static inline bool processFirmwareData(void)
{
    uint32_t        remainingBytes  {firmwareConfig.firmwareSize};
    uint32_t        offset          {0};
    uint32_t        pageOffset      {0};
    uint32_t        idx             {0};
    uint8_t        *dPtr            {firmwareConfig.newKey};
    bool            writeNewKey     {false};
    bool            result          {true};

    LED_ON();
    AES256::setKey(bootConfig.key);
    AES256::setIv(firmwareConfig.cipherIv);
    AES256::setOperation(AES256::DECRYPT);

    // Phase 1: Decrypt new key if provided in the header
    if (NEW_KEY_AES256 == GET_MODE_NEW_KEY_CIPHER())
    {
        AES256::cfbProcessBlock(dPtr);
        AES256::cfbProcessBlock(dPtr + AES256::BLOCK_SIZE);
        memcpy(&bootConfig.key, dPtr, AES256::KEY_SIZE);
        writeNewKey = true;
    }

    // Phase 2: Process firmware payload
    dPtr = buffer;
    memset(dPtr, 0xFF, PAGE_SIZE_BYTE);
    while ((remainingBytes > 0) && (true == result))
    {
        bool      isFullBlock {remainingBytes > (int32_t)AES256::BLOCK_SIZE};
        uint32_t  dataToRead  {isFullBlock ? (uint32_t)AES256::BLOCK_SIZE : remainingBytes};

        Flash::read((APP_STORE_BASE_ADDRESS + offset), (dPtr + idx), dataToRead);
        remainingBytes -= dataToRead;

        if (FIRMWARE_CIPHER_AES256 == GET_MODE_FIRMWARE_CIPHER())
        {
            AES256::cfbProcessBlock(dPtr + idx);
        }
        offset += dataToRead;
        idx += dataToRead;

        // Write buffer to Flash when page is full or end of data reached
        if ((idx >= PAGE_SIZE_BYTE) || (0 == remainingBytes))
        {
            uint8_t retry {OPERATION_RETRIES};
            do
            {
                result = Flash::writePage((APP_START_ADDRESS + pageOffset), dPtr);
            } while ((false == result) && --retry);
            
            memset(dPtr, 0xFF, PAGE_SIZE_BYTE);
            ledToggle(0x04);
            pageOffset += PAGE_SIZE_BYTE;
            idx = 0;
        }
    }

    // Update permanent storage with new key and metadata
    if ((true == result) && (true == writeNewKey))
    {
        result = NVStorage::write(ID_CIPHER_KEY, bootConfig.key, sizeof(bootConfig.key));
    }
    if (true == result)
    {
        memcpy(&bootConfig.firmwareSize, &firmwareConfig.firmwareSize, (sizeof(bootConfig.firmwareSize) + sizeof(bootConfig.firmwareCrc32)));
        result = NVStorage::write(ID_FIRMWARE_SIZE, (uint8_t *)&firmwareConfig.firmwareSize, sizeof(firmwareConfig.firmwareSize))
              && NVStorage::write(ID_FIRMWARE_CRC, (uint8_t *)&firmwareConfig.firmwareCrc32, sizeof(firmwareConfig.firmwareCrc32));
    }

    LED_OFF();
    return result;
}

/**
 * @brief Erases the firmware storage partition after successful installation.
 */
static inline void cleanStoredFirmware(void)
{
    uint32_t    address {FIRMWARE_STORE_BASE_ADDRESS};
    bool        result;

#   if defined(FLASH_BANK_1_ALLOWED) && FLASH_BANK_1_ALLOWED != 0
        fmc_unlock();
#   else
        fmc_bank0_unlock();
#   endif

    do
    {
        uint8_t retry {OPERATION_RETRIES};
        do
        {
            result = (FMC_READY == fmc_page_erase(address));
        } while ((false == result) && --retry);

        address += PAGE_SIZE_BYTE;
        ledToggle(0x01);
    } while ((address < (FIRMWARE_STORE_BASE_ADDRESS + firmwareConfig.firmwareSize)));

#   if defined(FLASH_BANK_1_ALLOWED) && FLASH_BANK_1_ALLOWED != 0
        fmc_lock();
#   else
        fmc_bank0_lock();
#   endif
}

/**
 * @brief Validates the current application using hardware-compatible CRC32 or Stack/PC checks.
 * @return true if application is safe to run.
 */
#if defined(APPLICATION_CRC_CHECK) && APPLICATION_CRC_CHECK == 1
static inline bool isApplicationValid(void)
{
    bool result {false};
    if (bootConfig.firmwareSize <= APP_MAX_SIZE)
    {
        CRC32::init();
        uint8_t    *appStartPtr {(uint8_t *)APP_START_ADDRESS};
        uint32_t    crc         {CRC32::update(appStartPtr, bootConfig.firmwareSize)};
        if (crc == bootConfig.firmwareCrc32)
        {
            result = true;
        }
        CRC32::end();
    }
    return result;
}
#else
static inline bool isApplicationValid(void)
{
    uint32_t   *vector_table    {(uint32_t *)APP_START_ADDRESS};
    uint32_t    sp              {vector_table[0]};
    uint32_t    pc              {vector_table[1]};

    // 1. Check if Stack Pointer is within RAM range
    if (sp < MCU_RAM_START || sp > MCU_RAM_END)
    {
        return false;
    }

    // 2. Check if Reset Vector (PC) is within Flash and Thumb bit is set
    if ((pc < APP_START_ADDRESS) || (!(pc & 1)))
    {
        return false;
    }
    return true;
}
#endif

/**
 * @brief Performs full MCU cleanup and jumps to the application entry point.
 * Safety measures:
 * - Disables interrupts (PRIMASK).
 * - Clears all NVIC pending/enabled interrupts.
 * - Resets peripherals and SysTick.
 * - Updates VTOR and MSP before branch.
 */
static inline void jumpToApplication(void)
{
    typedef void (*pFunction)(void);
    volatile uint32_t  *jumpAddressPtr      {(volatile uint32_t *)APP_START_ADDRESS};
    pFunction           goToApplication     {(pFunction)jumpAddressPtr[1]};

    __set_PRIMASK(1);
    __disable_irq();

    // Clear all NVIC enable and pending bits
    for (size_t idx = 0; idx < 8; idx++)
    {
        NVIC->ICER[idx] = 0xFFFFFFFF;
        NVIC->ICPR[idx] = 0xFFFFFFFF;
    }

#if defined(USE_LED) && USE_LED != 0
    rcu_periph_reset_enable(RCU_GPIOBRST);
    rcu_periph_reset_disable(RCU_GPIOBRST);
    rcu_periph_clock_disable(RCU_GPIOB);
#endif

    rcu_deinit();
    SysTick->CTRL = 0;
    SysTick->LOAD = 0;
    SysTick->VAL = 0;

    // Secure the jump
    SCB->VTOR = *jumpAddressPtr;
    __set_MSP(*jumpAddressPtr);
    __DSB();
    __ISB();
    
    __enable_irq();
    goToApplication();
}

/**
 * @brief Blinks the LED for visual status indication.
 * @param count Number of blinks.
 */
static void ledBlink(uint_fast8_t count)
{
    while (count--)
    {
        LED_ON();
        delay(20);
        LED_OFF();
        delay(145);
    }
}

/**
 * @brief Toggles the LED based on a bitmask for status signaling during flash operations.
 * @param mask Bitmask applied to internal state counter.
 */
static void ledToggle(uint8_t mask)
{
    static uint32_t state {0};
    ++state;
    if ((state & mask) != 0)
    {
        LED_ON();
    } else
    {
        LED_OFF();
    }
}
