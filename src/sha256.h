#pragma once
#include <Arduino.h>

/**
 * @file sha256.h
 * @namespace SHA256
 * @brief Namespace containing the implementation of the SHA-256 Secure Hash Algorithm.
 *
 * This implementation follows the FIPS 180-4 standard. It is designed
 * for embedded environments (Arduino) with minimal dependencies.
 * 
 * @copyright SPDX-FileCopyrightText: Copyright 2025-2026 by Michal Protasowicki
 * @license SPDX-License-Identifier: MIT license
 */
namespace SHA256
{
    /**
     * @brief The size of the resulting hash in bytes.
     * SHA-256 produces a 256-bit (32-byte) digest.
     */
    static constexpr uint8_t HASH_SIZE {32};

    /**
     * @struct context_t
     * @brief Holds the internal state of the SHA-256 hashing process.
     *
     * This structure persists the state between calls to update() blocks
     * of data.
     */
    typedef struct
    {
        uint8_t     data[64];   ///< 512-bit message block buffer.
        uint32_t    dataLen;    ///< Current length of data in the buffer (in bytes).
        uint64_t    bitLen;     ///< Total length of the message processed so far (in bits).
        uint32_t    state[8];   ///< Intermediate hash state (H0 to H7).
    } context_t;

    /**
     * @brief Initializes the SHA-256 context.
     *
     * Resets the state variables to the standard SHA-256 initial hash values
     * and clears the bit counters.
     *
     * @param ctx Pointer to the context structure to initialize.
     */
    void init(context_t *ctx);

    /**
     * @brief Updates the hash with new data.
     *
     * This function processes the input data in 64-byte blocks. Any remaining
     * bytes are buffered in the context until enough data is available to
     * fill a block or final() is called.
     *
     * @param ctx Pointer to the SHA-256 context.
     * @param data Pointer to the input data buffer.
     * @param dataLength Length of the input data in bytes.
     */
    void update(context_t *ctx, const uint8_t data[], size_t dataLength);

    /**
     * @brief Finalizes the hash computation and retrieves the digest.
     *
     * Performs padding (appending a '1' bit, zeros, and the message length),
     * processes the final block(s), and converts the state to a byte array.
     *
     * @param ctx Pointer to the SHA-256 context.
     * @param hash Output buffer where the 32-byte hash will be stored.
     * Must be at least HASH_SIZE bytes large.
     */
    void final(context_t *ctx, uint8_t hash[HASH_SIZE]);
}
