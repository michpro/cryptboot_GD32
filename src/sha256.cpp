
/**
 * @file sha256.cpp
 * @brief Namespace containing the implementation of the SHA-256 Secure Hash Algorithm.
 *
 * This implementation follows the FIPS 180-4 standard. It is designed
 * for embedded environments (Arduino) with minimal dependencies.
 * 
 * @copyright SPDX-FileCopyrightText: Copyright 2025-2026 by Michal Protasowicki
 * @license SPDX-License-Identifier: MIT license
 */

#include "sha256.h"

// -----------------------------------------------------------------------------
// Macro Definitions (FIPS 180-4 Section 4.1.2)
// -----------------------------------------------------------------------------

// CH(x, y, z) = (x & y) ^ (~x & z)
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))

// MA(x, y, z) = (x & y) ^ (x & z) ^ (y & z)
#define MA(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

// ROTR(x, n): Circular right rotate of 32-bit integer x by n bits.
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// SHA-256 Sigma functions
#define SUM0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SUM1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define R0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define R1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

namespace SHA256
{
    namespace
    {
        // SHA-256 Round Constants (K)
        static const uint32_t K[] =
        {
            0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
            0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
            0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
            0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
            0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
            0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
            0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
            0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
        };

        // Performs the main SHA-256 transformation on a 64-byte block.
        void transform(context_t *ctx, const uint8_t data[64])
        {
            uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

            // 1. Prepare the message schedule
            for (i = 0, j = 0; i < 16; ++i, j += 4) 
            {
                m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
            }
            for ( ; i < 64; ++i)
            {
                m[i] = R1(m[i - 2]) + m[i - 7] + R0(m[i - 15]) + m[i - 16];
            }

            // 2. Initialize working variables
            a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
            e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

            // 3. Compression Loop
            for (i = 0; i < 64; ++i)
            {
                t1 = h + SUM1(e) + CH(e, f, g) + K[i] + m[i];
                t2 = SUM0(a) + MA(a, b, c);
                h = g; g = f; f = e; e = d + t1;
                d = c; c = b; b = a; a = t1 + t2;
            }

            // 4. Update state
            ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
            ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
        }
    }

    void init(context_t *ctx)
    {
        // Initial Hash Values (H0..H7)
        ctx->state[0] = 0x6A09E667; ctx->state[1] = 0xBB67AE85; ctx->state[2] = 0x3C6EF372; ctx->state[3] = 0xA54FF53A;
        ctx->state[4] = 0x510E527F; ctx->state[5] = 0x9B05688C; ctx->state[6] = 0x1F83D9AB; ctx->state[7] = 0x5BE0CD19;

        ctx->bitLen = 0;
        ctx->dataLen = 0;
    }

    void update(context_t *ctx, const uint8_t data[], size_t dataLength)
    {
        for (uint32_t i = 0; i < dataLength; ++i)
        {
            ctx->data[ctx->dataLen] = data[i];
            ctx->dataLen++;
            // If the buffer is full (64 bytes), process the block
            if (64 == ctx->dataLen)
            {
                transform(ctx, ctx->data);
                ctx->bitLen += 512;
                ctx->dataLen = 0;
            }
        }
    }

    void final(context_t *ctx, uint8_t hash[HASH_SIZE])
    {
        uint32_t i {ctx->dataLen};

        // Padding Step 1: Append a single '1' bit (0x80 byte)
        ctx->data[i++] = 0x80;

        // Padding Step 2: Ensure there is space for the 8-byte length field.
        // We need 56 bytes of data + padding to leave 8 bytes at the end.
        if (i > 56)
        {
            // Not enough space: Pad with zeros to 64, transform, then reset.
            while (i < 64)
            {
                ctx->data[i++] = 0x00;
            }
            transform(ctx, ctx->data);
            i = 0; // Start fresh for the final block
        }

        // Pad with zeros up to 56 bytes
        while (i < 56)
        {
            ctx->data[i++] = 0x00;
        }

        // Padding Step 3: Append the total message length in bits (Big Endian).
        // bitLen tracks full blocks processed. dataLen is the remaining bytes.
        uint64_t totalBits = ctx->bitLen + (ctx->dataLen * 8);

        ctx->data[56] = totalBits >> 56;
        ctx->data[57] = totalBits >> 48;
        ctx->data[58] = totalBits >> 40;
        ctx->data[59] = totalBits >> 32;
        ctx->data[60] = totalBits >> 24;
        ctx->data[61] = totalBits >> 16;
        ctx->data[62] = totalBits >> 8;
        ctx->data[63] = totalBits;

        // Process the final block
        transform(ctx, ctx->data);

        // Output: Copy internal state (Big Endian) to the output hash buffer
        for (i = 0; i < 4; ++i)
        {
            hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
        }
    }
}
