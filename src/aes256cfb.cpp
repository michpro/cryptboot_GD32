/**
 * @file aes256cfb.cpp
 * @brief Implementation of AES-256 CFB mode.
 * 
 * @copyright SPDX-FileCopyrightText: Copyright 2025-2026 by Michal Protasowicki
 * @license SPDX-License-Identifier: MIT license
 */

#include "aes256cfb.h"

namespace AES256
{
    namespace
    {
        // AES-256 Parameters
        constexpr uint8_t   STATE_COLUMNS       {4};                            // Number of columns in state (Nb)
        constexpr uint8_t   KEY_WORDS           {KEY_SIZE / sizeof(uint32_t)};  // Key length in words (Nk) - 8 for 256-bit
        constexpr uint8_t   ROUNDS              {14};                           // Number of rounds (Nr) - 14 for 256-bit
        constexpr uint16_t  EXPANDED_KEY_SIZE   {BLOCK_SIZE * (ROUNDS + 1)};    // Total expanded key size
        constexpr uint16_t  SBOX_SIZE           {256};

        // Context holding the cipher state
        typedef struct context
        {
            uint8_t         expandedKey[EXPANDED_KEY_SIZE];
            uint8_t         iv[IV_SIZE];                            // Initialization Vector (functions as the feedback register)
            aesOperation_t  operation;
        } context_t;

        // Static instance (Not thread-safe, saves stack passing overhead)
        context_t ctx;

        // AES S-Box (Substitution Box)
        static const uint8_t sbox[SBOX_SIZE] =
        {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        };

        // Round constants (Rcon)
        static const uint8_t rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};

        /**
         * @brief Multiplies x by 2 in GF(2^8).
         * Optimization: Implemented branchless to avoid pipeline flushes and ensure constant time execution.
         */
        inline uint8_t xtime(uint8_t x)
        {
            // Branchless: if MSB is set, XOR with 0x1b, else XOR with 0.
            return (x << 1) ^ (0x1B & -static_cast<int8_t>(x >> 7));
        }

        /**
         * @brief Substitutes bytes using the S-Box.
         * Optimization: Working on flat array avoids 2D index calculation overhead.
         */
        void subBytes(uint8_t *state)
        {
            for (uint_fast8_t i = 0; i < BLOCK_SIZE; ++i)
            {
                state[i] = sbox[state[i]];
            }
        }

        /**
         * @brief Shifts rows of the state.
         * Optimization: Hardcoded indices for 1D array to save loop/calc overhead.
         */
        void shiftRows(uint8_t *state)
        {
            uint8_t tmp;

            // Row 1: Rotate left by 1 (Indices: 1, 5, 9, 13)
            tmp = state[1];
            state[1] = state[5];
            state[5] = state[9];
            state[9] = state[13];
            state[13] = tmp;

            // Row 2: Rotate left by 2 (Indices: 2, 6, 10, 14)
            tmp = state[2];
            state[2] = state[10];
            state[10] = tmp;
            tmp = state[6];
            state[6] = state[14];
            state[14] = tmp;

            // Row 3: Rotate left by 3 (Indices: 3, 7, 11, 15)
            tmp = state[3];
            state[3] = state[15];
            state[15] = state[11];
            state[11] = state[7];
            state[7] = tmp;
        }

        /**
         * @brief Mixes columns of the state.
         */
        void mixColumns(uint8_t *state)
        {
            for (uint_fast8_t i = 0; i < BLOCK_SIZE; i += 4)
            {
                uint8_t a0 = state[i];
                uint8_t a1 = state[i + 1];
                uint8_t a2 = state[i + 2];
                uint8_t a3 = state[i + 3];

                uint8_t t = a0 ^ a1 ^ a2 ^ a3;
                state[i]     ^= t ^ xtime(a0 ^ a1);
                state[i + 1] ^= t ^ xtime(a1 ^ a2);
                state[i + 2] ^= t ^ xtime(a2 ^ a3);
                state[i + 3] ^= t ^ xtime(a3 ^ a0);
            }
        }

        /**
         * @brief Adds the round key to the state.
         * Optimization: Direct memory XORing.
         */
        void addRoundKey(uint8_t round, uint8_t *state, const uint8_t *expandedKey)
        {
            const uint8_t* keyChunk = &expandedKey[round * BLOCK_SIZE];

            for (uint_fast8_t i = 0; i < BLOCK_SIZE; ++i)
            {
                state[i] ^= keyChunk[i];
            }
        }

        /**
         * @brief Encrypts a single block using AES-ECB (Electronic Codebook).
         * This is the primitive used for CFB mode.
         * Optimization: Uses a local buffer to avoid structure padding issues and keeps operations on the stack.
         */
        void aesEcbEncrypt(const uint8_t *input, const uint8_t *expandedKey, uint8_t *output)
        {
            // Copy input to local state (avoiding malloc/complex structs)
            uint8_t state[BLOCK_SIZE];

            memcpy(state, input, BLOCK_SIZE);

            addRoundKey(0, state, expandedKey);

            for (uint_fast8_t round = 1; round < ROUNDS; ++round)
            {
                subBytes(state);
                shiftRows(state);
                mixColumns(state);
                addRoundKey(round, state, expandedKey);
            }

            subBytes(state);
            shiftRows(state);
            addRoundKey(ROUNDS, state, expandedKey);

            // Copy result to output
            memcpy(output, state, BLOCK_SIZE);
        }

        void keyExpansion(const uint8_t *key, uint8_t *expandedKey)
        {
            uint8_t temp[4];
            uint_fast8_t i = 0;

            // Copy initial key
            for (i = 0; i < KEY_SIZE; i++)
            {
                expandedKey[i] = key[i];
            }

            i = KEY_WORDS;

            while (i < STATE_COLUMNS * (ROUNDS + 1))
            {
                // Read previous word
                for (uint_fast8_t k = 0; k < 4; k++)
                {
                    temp[k] = expandedKey[(i - 1) * 4 + k];
                }

                if (i % KEY_WORDS == 0)
                {
                    // RotWord
                    uint8_t tmp = temp[0];
                    temp[0] = temp[1];
                    temp[1] = temp[2];
                    temp[2] = temp[3];
                    temp[3] = tmp;

                    // SubWord + Rcon
                    for (uint_fast8_t k = 0; k < 4; k++)
                    {
                        temp[k] = sbox[temp[k]];
                    }
                    temp[0] ^= rcon[i / KEY_WORDS - 1];
                } else if ((KEY_WORDS > 6) && ((i % KEY_WORDS) == 4))
                {
                    // SubWord only (specific to AES-256)
                    for (uint_fast8_t k = 0; k < 4; k++)
                    {
                        temp[k] = sbox[temp[k]];
                    }
                }

                // XOR with word KEY_WORDS positions back
                for (uint_fast8_t k = 0; k < 4; k++)
                {
                    expandedKey[i * 4 + k] = expandedKey[(i - KEY_WORDS) * 4 + k] ^ temp[k];
                }

                i++;
            }
        }
    } // anonymous namespace

    void setKey(const uint8_t key[KEY_SIZE])
    {
        keyExpansion(key, ctx.expandedKey);
    }

    void setIv(const uint8_t iv[IV_SIZE])
    {
        memcpy(ctx.iv, iv, IV_SIZE);
    }

    void setOperation(const aesOperation_t operation)
    {
        ctx.operation = operation;
    }

    /**
     * @brief CFB (Cipher Feedback) Block processing.
     * * In CFB mode:
     *   1. The IV (Shift Register) is Encrypted.
     *   2. The result is XORed with Plaintext to produce Ciphertext.
     *   3. The Shift Register is updated with the Ciphertext (for both Encrypt and Decrypt).
     */
    void cfbProcessBlock(uint8_t buffer[BLOCK_SIZE])
    {
        // 1. Encrypt the current IV to create the "keystream" block
        // Note: CFB mode *always* uses the block encryption primitive, even when "decrypting" data.
        uint8_t keyStream[BLOCK_SIZE];

        aesEcbEncrypt(ctx.iv, ctx.expandedKey, keyStream);

        // 2. XOR data with keystream and update IV
        for (uint_fast8_t i = 0; i < BLOCK_SIZE; ++i)
        {
            uint8_t inputByte = buffer[i];
            
            // Perform the transform: Ciphertext = Plaintext ^ EncryptedIV
            buffer[i] ^= keyStream[i];

            // 3. Feedback: IV becomes the Ciphertext.
            // If Encrypting: The output buffer contains the Ciphertext.
            // If Decrypting: The input buffer contained the Ciphertext.
            if (ctx.operation == aesOperation_t::ENCRYPT)
            {
                ctx.iv[i] = buffer[i]; 
            } else
            {
                ctx.iv[i] = inputByte;
            }
        }
    }
}
