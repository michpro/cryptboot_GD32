/**
 * @file nvstorage.cpp
 * @brief Implementation of the Log-Structured NVStorage system for GD32F30x Flash.
 * 
 * @copyright SPDX-FileCopyrightText: Copyright 2025-2026 by Michal Protasowicki
 * @license SPDX-License-Identifier: MIT license
 */

#include "nvstorage.h"
#include "flash.h"
#include <cstring>                                                  // Required for memset/memcpy

namespace NVStorage
{
    // Constants
    constexpr uint8_t  CLR_ID {0x00};                               ///< Internal ID for clearing/maintenance
    constexpr uint8_t  MIN_ID {0x01};                               ///< Minimum valid user ID
    constexpr uint8_t  MAX_ID {0x7E};                               ///< Maximum valid user ID (7-bit limit)
    
    // Magic & Layout
    constexpr uint32_t PAGE_IDENTITY    {0xBEBAEDFE};               ///< Page validation magic number
    constexpr uint32_t HEADER_SIZE      {sizeof(uint16_t)};         ///< Size of the entry header
    constexpr uint16_t EMPTY_CELL       {0xFFFF};                   ///< Erased Flash state
    constexpr uint8_t  EMPTY_BYTE       {0xFF};

    // Internal State
    namespace
    {
#   if defined(USE_ONLY_FLASH_BANK0) && USE_ONLY_FLASH_BANK0 != 1
        constexpr uint32_t  MAX_PAGE_SIZE   {4096};                 ///< Maximum supported sector size
        uint32_t            pageSize;                               ///< Calculated page size in bytes
#   else
        constexpr uint32_t  MAX_PAGE_SIZE   {2048};                 ///< Maximum supported sector size
        constexpr uint32_t  pageSize        {MAX_PAGE_SIZE};        ///< Page size in bytes
#   endif
        uint32_t            baseAddress     {0};                    ///< Start address of the storage page
        bool                isReadable      {false};                ///< System status flag

        /**
         * @brief Unified scanner: Finds both the end of the list AND a specific ID.
         * @param[in]  targetId   ID to search for.
         * @param[out] matchAddr  Address of the LATEST header for targetId (if found).
         * @param[out] endAddr    Address of the first empty slot (end of list).
         * @return uint8_t        Data length of the found ID (0 if not found).
         */
        uint8_t scanPage(uint8_t targetId, uint32_t &matchAddr, uint32_t &endAddr)
        {
            uint32_t cursor     {baseAddress + sizeof(PAGE_IDENTITY)};
            uint32_t limit      {baseAddress + pageSize};
            uint16_t header;
            uint8_t  foundLen   {0};

            matchAddr = 0;                                          // Invalid address initially

            while (cursor < limit)
            {
                Flash::read(cursor, (uint8_t*)&header, HEADER_SIZE);

                if (EMPTY_CELL == header)
                {
                    break;
                }

                // Parse Header: [15: Padding] [14..8: ID] [7..0: Length]
                uint8_t id  {(uint8_t)((header & 0x7F00) >> 8)};
                uint8_t len {(uint8_t)(header & 0x00FF)};
                
                // Track the latest instance of the target ID
                if (id == targetId)
                {
                    matchAddr = cursor;
                    foundLen  = len;
                }

                // Advance cursor: Header + Data + PaddingByte (if bit 15 set)
                cursor += HEADER_SIZE + len + (header >> 15);
            }

            endAddr = cursor;

            return foundLen;
        }

        /**
         * @brief Garbage collector that consolidates valid data and erases the page.
         * @warning This function uses a 4KB stack buffer. Ensure the MCU stack is sufficient.
         */
        bool compactData(const uint8_t idForUpdate, const uint8_t* data, const uint8_t updateLen)
        {
            uint32_t unusedAddr;
            uint32_t freeEnd;
            
            // 1. Check current space usage
            scanPage(CLR_ID, unusedAddr, freeEnd);
            uint32_t currentUsed {freeEnd - baseAddress};
            
            // 2. Prepare RAM Buffer
            uint8_t buffer[MAX_PAGE_SIZE];
            memset(buffer, EMPTY_BYTE, sizeof(buffer));
            memcpy(buffer, &PAGE_IDENTITY, sizeof(PAGE_IDENTITY));

            uint32_t    bufIdx          {sizeof(PAGE_IDENTITY)};
            bool        updateWritten   {false};

            // 3. Iterate all valid IDs to rebuild the list in RAM
            for (uint8_t id = MIN_ID; id <= MAX_ID; ++id)
            {
                uint32_t        srcAddr;
                uint8_t         len             {0};
                bool            isUpdateTarget  {(id == idForUpdate && updateLen > 0)};
                const uint8_t  *srcPtr          {nullptr};

                if (isUpdateTarget)
                {
                    len = updateLen;
                    srcPtr = data;
                    updateWritten = true;
                } else
                {
                    len = scanPage(id, srcAddr, freeEnd);
                }

                if (len > 0)
                {
                    uint8_t padding {(uint8_t)(len % 2)};
                    
                    if (bufIdx + HEADER_SIZE + len + padding > pageSize)
                    {
                        return false; // Buffer overflow protection
                    }

                    // Write Header to Buffer: [PadBit << 15] | [ID << 8] | [Len]
                    uint16_t newHeader {(uint16_t)(((uint16_t)padding << 15) | ((uint16_t)id << 8) | len)};

                    buffer[bufIdx]     = newHeader & 0xFF;
                    buffer[bufIdx + 1] = (newHeader >> 8) & 0xFF;
                    bufIdx += HEADER_SIZE;

                    if (isUpdateTarget)
                    {
                        memcpy(&buffer[bufIdx], srcPtr, len);
                    } else
                    {
                        Flash::read(srcAddr + HEADER_SIZE, &buffer[bufIdx], len);
                    }
                    bufIdx += len + padding;
                }
            }

            // 4. Commit RAM buffer to Flash if space was saved or data updated
            if (bufIdx < currentUsed || updateWritten)
            {
                bool ret {Flash::writePage(baseAddress, buffer)};

                isReadable = ret;

                return ret;
            }
            
            return false;
        }
    }

    bool init(const uint32_t startAddress)
    {
        uint32_t magic;

        baseAddress = Flash::getPageStartAddress(startAddress);

#   if defined(USE_ONLY_FLASH_BANK0) && USE_ONLY_FLASH_BANK0 != 1
        pageSize = Flash::getPageSizeByte(startAddress);
#   endif

        Flash::read(baseAddress, (uint8_t *)&magic, sizeof(magic));

        if (magic != PAGE_IDENTITY)
        {
            // Format Page
#       if defined(FLASH_BANK_1_ALLOWED) && FLASH_BANK_1_ALLOWED != 0
            fmc_unlock();
#       else
            fmc_bank0_unlock();
#       endif

            bool ret {(FMC_READY == fmc_page_erase(baseAddress))};

            if (ret)
            {
                ret = (FMC_READY == fmc_word_program(baseAddress, PAGE_IDENTITY));
            }

#       if defined(FLASH_BANK_1_ALLOWED) && FLASH_BANK_1_ALLOWED != 0
            fmc_lock();
#       else
            fmc_bank0_lock();
#       endif

            isReadable = ret;

            return ret;
        }

        isReadable = true;
        
        // Force compact if page is dangerously full
        uint32_t dummy;
        uint32_t endAddr;

        scanPage(CLR_ID, dummy, endAddr);

        if ((baseAddress + pageSize - endAddr) <= (2 * HEADER_SIZE))
        {
            return compactData(CLR_ID, nullptr, 0);
        }

        return true;
    }

    uint8_t read(const uint8_t id, uint8_t data[])
    {
        if (!isReadable)
        {
            return 0;
        }
        
        uint32_t    matchAddr;
        uint32_t    endAddr;
        uint8_t     len {scanPage(id, matchAddr, endAddr)};

        if (len > 0 && data)
        {
            Flash::read(matchAddr + HEADER_SIZE, data, len);
        }

        return len;
    }

    bool write(const uint8_t id, const uint8_t data[], const uint8_t dataLength)
    {
        if (!isReadable || dataLength == 0)
        {
            return false;
        }
        if ((unsigned)(id - MIN_ID) > (MAX_ID - MIN_ID))
        {
            return false;
        }

        uint32_t matchAddr;
        uint32_t endAddr;

        scanPage(id, matchAddr, endAddr);

        uint8_t     padding     {(uint8_t)(dataLength % 2)};
        uint32_t    required    {HEADER_SIZE + dataLength + padding};
        uint32_t    freeSpace   {(baseAddress + pageSize) - endAddr};

        if (freeSpace < required)
        {
            if (compactData(id, data, dataLength))
            {
                return true;
            }
            
            scanPage(CLR_ID, matchAddr, endAddr);
            freeSpace = (baseAddress + pageSize) - endAddr;
            if (freeSpace < required)
            {
                return false;
            }
        }

        // Direct Flash Programming
#   if defined(FLASH_BANK_1_ALLOWED) && FLASH_BANK_1_ALLOWED != 0
        fmc_unlock();
#   else
        fmc_bank0_unlock();
#   endif

        bool        ret     {true};
        uint16_t    header  {(uint16_t)((padding << 15) | (id << 8) | dataLength)};

        if (FMC_READY != fmc_halfword_program(endAddr, header))
        {
            ret = false;
        }
        endAddr += HEADER_SIZE;

        if (ret)
        {
            const uint16_t *words       {(const uint16_t*)data};
            uint8_t         wordCount   {(uint8_t)(dataLength / 2)};
            
            for(int idx = 0; idx < wordCount && ret; idx++)
            {
                if (FMC_READY != fmc_halfword_program(endAddr, words[idx]))
                {
                    ret = false;
                }
                endAddr += sizeof(uint16_t);
            }

            if (ret && padding)
            {
                uint16_t lastWord {(uint16_t)(0xFF00 | data[dataLength - 1])};

                if (FMC_READY != fmc_halfword_program(endAddr, lastWord))
                {
                    ret = false;
                }
            }
        }
        
#   if defined(FLASH_BANK_1_ALLOWED) && FLASH_BANK_1_ALLOWED != 0
        fmc_lock();
#   else
        fmc_bank0_lock();
#   endif

        return ret;
    }
}
