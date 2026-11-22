
/**
 * @file flash.cpp
 * @brief Implementation of Flash memory management optimized for ARM Cortex-M4.
 * 
 * @copyright SPDX-FileCopyrightText: Copyright 2025-2026 by Michal Protasowicki
 * @license SPDX-License-Identifier: MIT license
 */

#include "flash.h"

// Note: Ensure fmc_* functions (HAL) are available in the build context.

namespace Flash
{
# if DUAL_BANK_FLASH
    uint32_t getPageSizeByte(const uint32_t address)
    {
        return (FMC_BANK0_END_ADDRESS > address) ? 2048 : 4096;
    }
# else
    uint32_t getPageSizeByte(__attribute__ ((unused)) const uint32_t address)
    {
        return 2048;
    }
# endif

    uint32_t getPageStartAddress(const uint32_t address)
    {
        // Optimization: Use bitwise AND instead of modulo (%).
        // Because PAGE_SIZE_BYTE is a power of 2 (2048), ~(2048 - 1) 
        // creates a mask (0xFFFFF800) that clears the lower bits.
        // This saves expensive division instructions.
        return (address & ~(getPageSizeByte(address) - 1));
    }

    void read(const uint32_t startAddress, uint8_t data[], const uint32_t dataLength)
    {
        // Direct pointer access. 
        // On M4, this compiles to efficient LDRB/STRB instructions.
        const uint8_t *src {(const uint8_t *)startAddress};

        for (uint32_t idx = 0; idx < dataLength; idx++)
        {
            data[idx] = src[idx];
        }
    }

    bool isPageEmpty(const uint32_t startAddress)
    {
        const uint32_t  alignedAddr {getPageStartAddress(startAddress)};
        const uint32_t *ptr         {(const uint32_t *)alignedAddr};
        
        // Calculate the end pointer to avoid calculating size inside the loop
        const uint32_t *endPtr      {ptr + (getPageSizeByte(startAddress) / sizeof(uint32_t))};

        while (ptr < endPtr)
        {
            // Flash erased state is 0xFFFFFFFF
            if (*ptr++ != 0xFFFFFFFF)
            {
                return false;
            }
        }
        
        return true;
    }

    bool writePage(const uint32_t startAddress, uint8_t data[])
    {
        bool        result  {true};
        uint32_t    address {getPageStartAddress(startAddress)};

        // 1. Critical Section: Unlock Flash Memory Controller
#   if DUAL_BANK_FLASH
        fmc_unlock();
#   else
        fmc_bank0_unlock();
#   endif

        // 2. Erase if necessary
        // Flash can only flip bits from 1 to 0. To write new data, 
        // we must ensure the page is reset (all 1s) first.
        if (false == isPageEmpty(address))
        {
            result = (FMC_READY == fmc_page_erase(address));
        }

        // 3. Program the data
        if (true == result)
        {
            // Cast byte-stream to 32-bit words for the FMC
            uint32_t   *dptr        {(uint32_t *)data};
            uint32_t    pageSize    {getPageSizeByte(startAddress)};

            do
            {
                // Write one word (4 bytes) at a time
                result = (FMC_READY == fmc_word_program(address, *dptr++));
                address += sizeof(uint32_t);

            // Loop until the address wraps to the next page alignment
            } while ((0 != (address % pageSize)) && (true == result));
        }

        // 4. Verify by readback before locking: a silent programming bit-flip
        // must surface here (caller's retry loop engages) instead of hiding
        // until the whole-image CRC check. Read cost is negligible next to
        // erase/program time, and no extra RAM is needed (word-by-word).
        if (true == result)
        {
            const uint32_t  *expect {(const uint32_t *)data};
            const uint32_t  *actual {(const uint32_t *)address - (getPageSizeByte(startAddress) / sizeof(uint32_t))};
            const uint32_t  *end    {expect + (getPageSizeByte(startAddress) / sizeof(uint32_t))};

            while ((expect < end) && (true == result))
            {
                if (*expect++ != *actual++)
                {
                    result = false;
                }
            }
        }

        // 5. Critical Section: Lock Flash Memory Controller
#   if DUAL_BANK_FLASH
        fmc_lock();
#   else
        fmc_bank0_lock();
#   endif

        return result;
    }
}
