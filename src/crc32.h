/**
 * @file crc32.h
 * @brief Hardware-accelerated CRC32 calculation driver for GD32F30x.
 * @details This header provides an interface to the GD32 hardware CRC engine.
 * The calculation uses the following polynomial:
 * - Polynomial: 0x04C11DB7 (x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1)
 * - Input/Output: Not reflected by default.
 * - Initial Value: 0xFFFFFFFF.
 * 
 * @copyright SPDX-FileCopyrightText: Copyright 2025-2026 by Michal Protasowicki
 * @license SPDX-License-Identifier: MIT license
 */

#pragma once

#include <Arduino.h>

#ifndef GD32F30x
#   error "Unsupported MCU!!! This driver requires the GD32F30x firmware library."
#endif

/**
 * @namespace CRC32
 * @brief Contains functions to interface with the Hardware CRC Calculation Unit.
 */
namespace CRC32
{
    /**
     * @brief Resets the CRC data register to its initial value (0xFFFFFFFF).
     */
    inline void reset(void)
    {
        crc_data_register_reset();
    }

    /**
     * @brief Reads the current result from the CRC data register.
     * @return uint32_t The current 32-bit CRC checksum.
     */
    inline uint32_t get(void)
    {
        return crc_data_register_read();
    }

    /**
     * @brief Initializes the CRC peripheral clock and resets the register.
     * @note Must be called before any calculation.
     */
    inline void init(void)
    {
        rcu_periph_clock_enable(RCU_CRC);
        reset();
    }

    /**
     * @brief Deinitializes the CRC peripheral and disables the clock to save power.
     */
    inline void end(void)
    {
        crc_deinit();
        rcu_periph_clock_disable(RCU_CRC);
    }

    /**
     * @brief Performs a hardware-accelerated calculation on a single 32-bit word.
     * @param data The 32-bit data word to process.
     * @return uint32_t The resulting CRC-32 checksum.
     */
    inline uint32_t update(const uint32_t data)
    {
        return crc_single_data_calculate(data);
    }

    /**
     * @brief Updates the CRC calculation with a buffer of data.
     * @param buffer Pointer to the data array. For optimal performance, this pointer should be 4-byte aligned.
     * @param length Number of bytes to process.
     * @return uint32_t The calculated CRC-32 checksum.
     */
    uint32_t update(const uint8_t *buffer, const size_t length);
}
