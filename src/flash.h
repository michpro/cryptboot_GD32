/**
 * @file flash.h
 * @brief Flash memory management interface.
 * This module provides a namespace for interacting with the device's internal flash memory,
 * including reading, checking status, and writing full pages.
 * 
 * @copyright SPDX-FileCopyrightText: Copyright 2025-2026 by Michal Protasowicki
 * @license SPDX-License-Identifier: MIT license
 */

#pragma once

# ifndef GD32F30x
#   error Unsupported MCU!!!
# endif

#define FLASH_BANK_1_ALLOWED    0

#include <Arduino.h>

namespace Flash
{
    uint32_t getPageSizeByte(const uint32_t address);

    /**
     * @brief Calculates the start address of the page containing the given address.
     * @param address Any valid address within the flash memory space.
     * @return uint32_t The aligned start address of the page.
     */
    uint32_t getPageStartAddress(const uint32_t address);

    /**
     * @brief Reads data from flash memory into a buffer.
     * @note This function performs a direct memory copy.
     * @param startAddress The physical flash address to start reading from.
     * @param data Array to store the read data.
     * @param dataLength Number of bytes to read.
     */
    void read(const uint32_t startAddress, uint8_t data[], const uint32_t dataLength);

    /**
     * @brief Checks if a specific flash page is completely empty.
     * Optimization: Checks 32-bit words directly from flash to avoid RAM buffer overhead.
     * @param startAddress The address to check (automatically aligned to page start).
     * @return true If the entire page contains only 0xFF.
     * @return false If any bit in the page is set to 0.
     */
    bool isPageEmpty(const uint32_t startAddress);

    /**
     * @brief Writes a full page of data to flash memory.
     * Handles unlocking, erasing (if needed), and programming.
     * @warning The `data` buffer MUST contain exactly `PAGE_SIZE_BYTE` bytes.
     * passing a smaller buffer will cause a read overrun.
     * @param startAddress  The target address (will be aligned to the page start).
     * @param data          Pointer to the buffer containing the full page of data.
     * @return true If the write was successful.
     * @return false If an FMC error occurred.
     */
    bool writePage(const uint32_t startAddress, uint8_t data[]);
};
