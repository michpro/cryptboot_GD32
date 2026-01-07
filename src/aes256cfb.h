/**
 * @file aes256cfb.h
 * @brief AES-256 Cipher Feedback (CFB) Mode implementation.
 *
 * This module provides a lightweight implementation of the AES-256 encryption
 * algorithm in CFB128 mode, optimised for a balance between speed and code size.
 *
 * @note This implementation uses a static context and is NOT thread-safe.
 * 
 * @copyright SPDX-FileCopyrightText: Copyright 2025-2026 by Michal Protasowicki
 * @license SPDX-License-Identifier: MIT license
 */

#pragma once

#include <Arduino.h>

namespace AES256
{
    // Constants defining the AES-256 specific parameters
    constexpr uint8_t KEY_SIZE      {32};   ///< 256-bit key size in bytes
    constexpr uint8_t BLOCK_SIZE    {16};   ///< 128-bit block size in bytes
    constexpr uint8_t IV_SIZE       {16};   ///< 128-bit Initialization Vector size in bytes

    /**
     * @brief Defines the cipher operation mode.
     */
    typedef enum AesOperation : uint8_t
    {
        ENCRYPT = 0x00,
        DECRYPT,
    } aesOperation_t;

    /**
     * @brief Initializes the AES context with the provided key.
     * Performs key expansion. This must be called before any encryption/decryption.
     * @param[in] key Pointer to the 32-byte (256-bit) key.
     */
    void setKey(const uint8_t key[KEY_SIZE]);

    /**
     * @brief Sets the Initialization Vector (IV).
     * For CFB mode, the IV is updated continuously. When starting a new message chain, reset the IV using this function.
     * @param[in] iv Pointer to the 16-byte (128-bit) IV.
     */
    void setIv(const uint8_t iv[IV_SIZE]);

    /**
     * @brief Sets the operation mode (ENCRYPT or DECRYPT).
     * @param[in] operation The operation to perform.
     */
    void setOperation(const aesOperation_t operation);

    /**
     * @brief Processes a single block of data using AES-256-CFB.
     * This function encrypts or decrypts a 16-byte block in-place based on
     * the currently set operation and updates the internal IV state.
     * @param[in,out] buffer Pointer to the 16-byte data block to process.
     */
    void cfbProcessBlock(uint8_t buffer[BLOCK_SIZE]);
}
