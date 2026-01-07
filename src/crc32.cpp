/**
 * @file crc32.cpp
 * @brief Implementation of hardware-accelerated CRC32 update logic.
 * @details Uses the hardware engine with polynomial 0x04C11DB7.
 * 
 * @copyright SPDX-FileCopyrightText: Copyright 2025-2026 by Michal Protasowicki
 * @license SPDX-License-Identifier: MIT license
 */

#include "crc32.h"

namespace CRC32
{
    /**
     * @details The hardware engine processes data in 32-bit words.
     * This function splits the input buffer into whole words for the hardware,
     * then handles any remaining 1-3 bytes by padding them into a final 32-bit word.
     */
    uint32_t update(const uint8_t *buffer, const size_t length)
    {
        if ((nullptr == buffer) || (0 == length))
        {
            return get();
        }

        // Pointer for word-wise access
        const uint32_t *dPtr32 {reinterpret_cast<const uint32_t *>(buffer)};
        size_t          words  {length >> 2};                       // Fast divide by 4

        // 1. Process 32-bit words (Main Loop)
        while (words--)
        {
            // Direct write to hardware register
            CRC_DATA = *dPtr32++; 
        }

        // 2. Handle remaining 1-3 bytes
        uint32_t remainder {static_cast<uint32_t>(length & 0x03)};

        if (remainder > 0)
        {
            uint32_t        finalWord {0};
            // Point to the start of the remaining bytes
            const uint8_t  *dPtr8     {reinterpret_cast<const uint8_t *>(dPtr32)};

            for (uint32_t idx = 0; idx < remainder; idx++)
            {
                // Construct the final word
                finalWord |= static_cast<uint32_t>(dPtr8[idx]) << (24 - (idx * 8));
            }

            CRC_DATA = finalWord;
        }

        return get();
    }
}
