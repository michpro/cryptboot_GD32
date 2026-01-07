/**
 * @file nvstorage.h
 * @brief Header file for the Non-Volatile Storage (NVStorage) module.
 * This module implements a simple Log-Structured storage system on top of raw Flash memory.
 * It allows saving byte arrays associated with specific 8-bit IDs, using a sequential write 
 * strategy to maximize flash longevity and efficiency.
 * 
 * @copyright SPDX-FileCopyrightText: Copyright 2025-2026 by Michal Protasowicki
 * @license SPDX-License-Identifier: MIT license
 */

#pragma once

#include <Arduino.h>

#ifndef GD32F30x
#   error Unsupported MCU!!!
#endif

#define USE_ONLY_FLASH_BANK0    1

/**
 * @namespace NVStorage
 * @brief Non-Volatile Storage Manager.
 * @details
 * - Storage Strategy: Sequential append-only log.
 * - Identification: Data is stored as (Header + Data).
 * - Garbage Collection: Automatic compaction when the flash page is full.
 */
namespace NVStorage
{
    /**
     * @brief Initializes the storage system.
     * Verifies the storage page validity by checking the magic number (Page Identity).
     * If the page is invalid, it erases and formats the page.
     * If the page is valid but nearly full, it triggers a compaction to reclaim space.
     * @param startAddress The physical Flash memory address where the storage page begins.
     * @return true if initialization (and potential formatting) was successful.
     * @return false if there was a hardware failure or flash error.
     */
    bool init(const uint32_t startAddress);

    /**
     * @brief Reads the latest data associated with a specific ID.
     * Scans the storage page to find the most recent entry for the given ID.
     * @param id[in]    The unique identifier for the data (Valid range: 1-126).
     * @param data[out] Pointer to the buffer where read data will be copied.
     * @warning The buffer must be large enough to hold the stored data.
     * @return uint8_t The number of bytes read. Returns 0 if ID is not found or system is not readable.
     */
    uint8_t read(const uint8_t id, uint8_t data[]);

    /**
     * @brief Writes data to storage associated with a specific ID.
     * Appends the new data to the end of the log. If there is insufficient space,
     * it triggers a "Compact/Garbage Collect" operation to consolidate valid data and erase old entries before writing.
     * @param id[in]         The unique identifier for the data.
     * @param data[in]       Pointer to the data to be written.
     * @param dataLength[in] The number of bytes to write (Max length limited by header bits).
     * @return true if the write operation (and potential compaction) was successful.
     * @return false if the write failed, ID is invalid, or flash error occurred.
     */
    bool write(const uint8_t id, const uint8_t data[], const uint8_t dataLength);
}
