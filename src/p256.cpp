/**
 * @file p256.cpp
 * @brief Implementation of P-256 arithmetic operations.
 *
 * This file contains the low-level mathematical primitives (Montgomery multiplication,
 * Point addition/doubling in Jacobian coordinates) and the high-level protocol logic.
 *
 * Specific optimizations included for ARM processors via inline assembly.
 * 
 * @copyright SPDX-FileCopyrightText: Copyright 2025-2026 by Michal Protasowicki
 * @license SPDX-License-Identifier: MIT license
 */

#include "p256.h"

namespace P256
{
    namespace
    {
        /**
         * @struct ModulusContext
         * @brief Context for Montgomery modular arithmetic constants.
         */
        typedef struct
        {
            uint32_t modulus[8];    ///< The prime modulus (m).
            uint32_t R2[8];         ///< R^2 mod m, where R = 2^256.
            uint32_t negModInverse; ///< -m^-1 mod 2^32 (used for reduction).
        } ModulusContext;

        /**
         * @brief Constants for operations modulo the curve's field prime p.
         * p = 2^256 - 2^224 + 2^192 + 2^96 - 1
         */
        static const ModulusContext CONTEXT_P =
        {
            {                                                       // The curve's p
                0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
                0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF,
            },
            {                                                       // 2^512 mod p
                0x00000003, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFB,
                0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0x00000004,
            },
            0x00000001,                                             // -p^-1 mod 2^32
        };

        /**
         * @brief Constants for operations modulo the curve's order n.
         */
        static const ModulusContext CONTEXT_N =
        {
            {                                                       // The curve's n
                0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
                0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF,
            },
            {                                                       // 2^512 mod n
                0xBE79EEA2, 0x83244C95, 0x49BD6FA6, 0x4699799C,
                0x2B6BEC59, 0x2845B239, 0xF3D95620, 0x66E12D94,
            },
            0xEE00BC4F,                                             // -n^-1 mod 2^32
        };

        // The curve's b parameter in the Short Weierstrass equation y^2 = x^3 - 3*x + b
        // Pre-converted to the Montgomery domain.
        static const uint32_t CURVE_B_MONTGOMERY[8] =
        { // b * 2^256 mod p
            0x29C4BDDF, 0xD89CDF62, 0x78843090, 0xACF005CD,
            0xF7212ED6, 0xE5A220AB, 0x04874834, 0xDC30061D,
        };

        // The curve's generator point G (Montgomery domain).
        static const uint32_t GENERATOR_X[8] =
        {                                                           // G_x * 2^256 mod p
            0x18A9143C, 0x79E730D4, 0x5FEDB601, 0x75BA95FC,
            0x77622510, 0x79FB732B, 0xA53755C6, 0x18905F76,
        };
        static const uint32_t GENERATOR_Y[8] =
        {                                                           // G_y * 2^256 mod p
            0xCE95560A, 0xDDF25357, 0xBA19E45C, 0x8B4AB8E4,
            0xDD21F325, 0xD2E88688, 0x25885D85, 0x8571FF18,
        };

        RandomFunction rngFunc {nullptr};

        /**
         * @brief Fills a 32-byte buffer with random data.
         * Falls back to 0xFF00FF00 filler if no RNG function is attached.
         */
        void fillRandom(uint8_t buffer[32])
        {
            uint32_t *u32Buffer {(uint32_t *)buffer};
            
            for (uint8_t i = 0; i < (32 / sizeof(uint32_t)); ++i)
            {
                u32Buffer[i] = (rngFunc != nullptr) ? (uint32_t)rngFunc() : 0xFF00FF00;
            }
        }

        /**
         * @brief Securely zeroize memory (prevents compiler optimization removal).
         */
        static void secureZero(void *d, size_t n)
        {
            volatile char *p {(volatile char*)d};

            while(n--)
            {
                *p++ = 0x00;
            }
        }

        // --------------------------------------------------------------------------
        // Big Integer Arithmetic (Standard Domain)
        // --------------------------------------------------------------------------

        /*
        * 256-bit set to 32-bit value
        */
        static void bigIntSet32(uint32_t z[8], uint32_t x)
        {
            z[0] = x;
            for (uint_fast8_t i = 1; i < 8; i++)
            {
                z[i] = 0;
            }
        }

        /*
        * 256-bit addition
        * out: z = (x + y) mod 2^256
        * return: carry
        */
        static uint32_t bigIntAdd(uint32_t z[8], const uint32_t x[8], const uint32_t y[8])
        {
            uint32_t carry {0};

            for (uint_fast8_t i = 0; i < 8; i++)
            {
                uint64_t sum {(uint64_t)carry + x[i] + y[i]};

                z[i] = (uint32_t)sum;
                carry = (uint32_t)(sum >> 32);
            }

            return carry;
        }

        /*
        * 256-bit subtraction
        * out: z = (x - y) mod 2^256
        * return: borrow (1 if y > x, 0 otherwise)
        */
        static uint32_t bigIntSub(uint32_t z[8], const uint32_t x[8], const uint32_t y[8])
        {
            uint32_t carry {0};

            for (uint_fast8_t i = 0; i < 8; i++)
            {
                uint64_t diff {(uint64_t) x[i] - y[i] - carry};

                z[i] = (uint32_t)diff;
                carry = -(uint32_t)(diff >> 32);
            }

            return carry;
        }

        /*
        * 256-bit conditional assignment (Constant Time)
        * out: z = x if c == 1, z unchanged otherwise
        */
        static void bigIntCondAssign(uint32_t z[8], const uint32_t x[8], uint32_t c)
        {
            const uint32_t x_mask {-c};

            for (uint_fast8_t i = 0; i < 8; i++)
            {
                z[i] = (z[i] & ~x_mask) | (x[i] & x_mask);
            }
        }

        /*
        * 256-bit compare for equality
        * return: 0 if x == y, non-zero otherwise
        */
        static uint32_t bigIntCmpEq(const uint32_t x[8], const uint32_t y[8])
        {
            uint32_t diff {0};

            for (uint_fast8_t i = 0; i < 8; i++)
            {
                diff |= x[i] ^ y[i];
            }

            return diff;
        }

        /*
        * 256-bit compare to zero
        * return: 0 if x == 0, non-zero otherwise
        */
        static uint32_t bigIntCmpZero(const uint32_t x[8])
        {
            uint32_t diff {0};

            for (uint_fast8_t i = 0; i < 8; i++)
            {
                diff |= x[i];
            }

            return diff;
        }

        // --------------------------------------------------------------------------
        // Assembly Optimizations (Multiply Accumulate)
        // --------------------------------------------------------------------------

        /*
        * 32 x 32 -> 64-bit multiply-and-accumulate
        * out: x * y + z + t in [0, 2^64)
        */
        static uint64_t multiplyAccumulate64(uint32_t x, uint32_t y, uint32_t z, uint32_t t);

        #undef MULADD64_ASM
        #undef MULADD64_SMALL

        // Check for ARM GCC/Clang and specific profiles (M or A series)
        #if defined(__GNUC__) &&\
            defined(__ARM_ARCH) && __ARM_ARCH >= 6 && defined(__ARM_ARCH_PROFILE) && \
            ( __ARM_ARCH_PROFILE == 77 || __ARM_ARCH_PROFILE == 65 ) // 'M' or 'A'

        #if defined(__ARM_FEATURE_DSP)

        /**
         * @brief Assembly optimization using UMAAL (Unsigned Multiply Accumulate Accumulate Long).
         * Available on ARM Cortex-M4, M7, M33, etc. This is a 1-cycle instruction.
         */
        static uint64_t multiplyAccumulate64(uint32_t x, uint32_t y, uint32_t z, uint32_t t)
        {
            __asm__(
                // UMAAL <RdLo>, <RdHi>, <Rn>, <Rm>
                "umaal   %[z], %[t], %[x], %[y]"
                : [z] "+l" (z), [t] "+l" (t)
                : [x] "l" (x), [y] "l" (y)
            );
            return ((uint64_t)t << 32) | z;
        }
        #define MULADD64_ASM
        #define MULADD64_SMALL

        #else // __ARM_FEATURE_DSP

        // Fallback for M0, M0+, M23 (No DSP extensions)
        static uint64_t multiplyAccumulate64(uint32_t x, uint32_t y, uint32_t z, uint32_t t)
        {
            uint32_t tmp1, tmp2, tmp3;
            __asm__(
                ".syntax unified\n\t"
                "lsrs    %[u], %[x], #16\n\t"
                "lsrs    %[v], %[y], #16\n\t"
                "uxth    %[x], %[x]\n\t"
                "uxth    %[y], %[y]\n\t"
                "movs    %[w], %[v]\n\t"
                "muls    %[w], %[u]\n\t"
                "muls    %[v], %[x]\n\t"
                "muls    %[x], %[y]\n\t"
                "muls    %[y], %[u]\n\t"
                "lsls    %[u], %[y], #16\n\t"
                "lsrs    %[y], %[y], #16\n\t"
                "adds    %[x], %[u]\n\t"
                "adcs    %[y], %[w]\n\t"
                "lsls    %[u], %[v], #16\n\t"
                "lsrs    %[v], %[v], #16\n\t"
                "adds    %[x], %[u]\n\t"
                "adcs    %[y], %[v]\n\t"
                : [x] "+l" (x), [y] "+l" (y),
                [u] "=&l" (tmp1), [v] "=&l" (tmp2), [w] "=&l" (tmp3)
                : // no read-only inputs
                : "cc"
            );
            (void) tmp1; (void) tmp2; (void) tmp3;

            __asm__(
                ".syntax unified\n\t"
                "movs    %[u], #0\n\t"
                "adds    %[x], %[z]\n\t"
                "adcs    %[y], %[u]\n\t"
                "adds    %[x], %[t]\n\t"
                "adcs    %[y], %[u]\n\t"
                : [x] "+l" (x), [y] "+l" (y), [u] "=&l" (tmp1)
                : [z] "l" (z), [t] "l" (t)
                : "cc"
            );
            (void) tmp1;
            return ((uint64_t)y << 32) | x;
        }
        #define MULADD64_ASM

        #endif // __ARM_FEATURE_DSP

        #endif // GCC/Clang with Cortex-M/A CPU

        #if !defined(MULADD64_ASM)
        #if defined(MUL64_IS_CONSTANT_TIME)
        static uint64_t multiplyAccumulate64(uint32_t x, uint32_t y, uint32_t z, uint32_t t)
        {
            return (uint64_t)x * y + z + t;
        }
        #define MULADD64_SMALL
        #elif defined(__ARM_ARCH_4T__)
        static uint64_t multiplyAccumulate64(uint32_t x, uint32_t y, uint32_t z, uint32_t t)
        {
            uint32_t lo, hi;
            __asm__ volatile (
                "umull   %[lo], %[hi], %[x], %[y] \n\t" // hi:lo = x * y
                "adds    %[lo], %[lo], %[z]       \n\t" // lo += z
                "adcs    %[hi], %[hi], #0         \n\t" // hi += carry
                "adds    %[lo], %[lo], %[t]       \n\t" // lo += t
                "adcs    %[hi], %[hi], #0         \n\t" // hi += carry
                : [lo] "=&r" (lo), [hi] "=&r" (hi)
                : [x] "r" (x), [y] "r" (y), [z] "r" (z), [t] "r" (t)
                : "cc"
            );
            return ((uint64_t)hi << 32) | lo;
        }
        #else
        /**
         * @brief Generic C implementation of 32x32->64 multiply-add.
         * Decomposes into 16-bit operations to ensure no overflow and portability.
         */
        static uint64_t multiplyAccumulate64(uint32_t x, uint32_t y, uint32_t z, uint32_t t)
        {
            const uint16_t xl {(uint16_t)x};
            const uint16_t yl {(uint16_t)y};
            const uint16_t xh {x >> 16};
            const uint16_t yh {y >> 16};

            const uint32_t lo {(uint32_t)xl * yl};
            const uint32_t m1 {(uint32_t)xh * yl};
            const uint32_t m2 {(uint32_t)xl * yh};
            const uint32_t hi {(uint32_t)xh * yh};

            uint64_t acc {lo + ((uint64_t)(hi + (m1 >> 16) + (m2 >> 16)) << 32)};

            acc += m1 << 16;
            acc += m2 << 16;
            acc += z;
            acc += t;

            return acc;
        }
        #endif // MUL64_IS_CONSTANT_TIME
        #endif // MULADD64_ASM

        // --------------------------------------------------------------------------
        // Modular Arithmetic (Montgomery Domain)
        // --------------------------------------------------------------------------

        /*
        * 288-bit multiply and add helper
        * out: z_out = z_in + x * y mod 2^288
        */
        static uint32_t multiplyAccumulate288(uint32_t z[9], uint32_t x, const uint32_t y[8])
        {
            uint32_t carry {0};

        #define U288_MULADD_STEP(i)                                         \
            do                                                              \
            {                                                               \
                uint64_t prod {multiplyAccumulate64(x, y[i], z[i], carry)}; \
                                                                            \
                z[i] = (uint32_t)prod;                                      \
                carry = (uint32_t)(prod >> 32);                             \
            } while(0)

        #if defined(MULADD64_SMALL)
            U288_MULADD_STEP(0); U288_MULADD_STEP(1);
            U288_MULADD_STEP(2); U288_MULADD_STEP(3);
            U288_MULADD_STEP(4); U288_MULADD_STEP(5);
            U288_MULADD_STEP(6); U288_MULADD_STEP(7);
        #else
            for (uint_fast8_t i = 0; i < 8; i++)
            {
                U288_MULADD_STEP(i);
            }
        #endif

            uint64_t sum {(uint64_t)z[8] + carry};

            z[8] = (uint32_t)sum;
            carry = (uint32_t)(sum >> 32);

            return carry;
        }

        /*
        * 288-bit in-place right shift by 32 bits
        */
        static void bigIntRightShift32(uint32_t z[9], uint32_t c)
        {
            for (uint_fast8_t i = 0; i < 8; i++)
            {
                z[i] = z[i + 1];
            }
            z[8] = c;
        }

        /*
        * Import big integer from bytes
        */
        static void bigIntFromBytes(uint32_t z[8], const uint8_t p[32])
        {
            for (uint_fast8_t i = 0; i < 8; i++)
            {
                uint_fast8_t j {4 * (7 - i)};

                z[i] =  ((uint32_t)p[j + 0] << 24) |
                        ((uint32_t)p[j + 1] << 16) |
                        ((uint32_t)p[j + 2] <<  8) |
                        ((uint32_t)p[j + 3] <<  0);
            }
        }

        /*
        * Export big integer to bytes
        */
        static void bigIntToBytes(uint8_t p[32], const uint32_t z[8])
        {
            for (uint_fast8_t i = 0; i < 8; i++)
            {
                uint_fast8_t j {4 * (7 - i)};

                p[j + 0] = (uint8_t)(z[i] >> 24);
                p[j + 1] = (uint8_t)(z[i] >> 16);
                p[j + 2] = (uint8_t)(z[i] >>  8);
                p[j + 3] = (uint8_t)(z[i] >>  0);
            }
        }

        /*
        * Modular addition
        * out: z = (x + y) mod m
        */
        static void modAdd(uint32_t z[8], const uint32_t x[8], const uint32_t y[8], const ModulusContext *ctx)
        {
            uint32_t r[8];
            uint32_t carry_add  {bigIntAdd(z, x, y)};
            uint32_t carry_sub  {bigIntSub(r, z, ctx->modulus)};
            
            // Subtract modulus if:
            // x+y >= 2^256 (carry_add == 1) OR result >= modulus (carry_sub == 0)
            uint32_t use_sub    {carry_add | (1 - carry_sub)};

            bigIntCondAssign(z, r, use_sub);
        }

        static void modAddP(uint32_t z[8], const uint32_t x[8], const uint32_t y[8])
        {
            modAdd(z, x, y, &CONTEXT_P);
        }

        /*
        * Modular subtraction
        * out: z = (x - y) mod m
        */
        static void modSub(uint32_t z[8], const uint32_t x[8], const uint32_t y[8], const ModulusContext *ctx)
        {
            uint32_t r[8];
            uint32_t carry {bigIntSub(z, x, y)};

            (void)bigIntAdd(r, z, ctx->modulus);
            // If carry == 1 (x < y), we need to add the modulus back
            bigIntCondAssign(z, r, carry);
        }

        static void modSubP(uint32_t z[8], const uint32_t x[8], const uint32_t y[8])
        {
            modSub(z, x, y, &CONTEXT_P);
        }

        /*
        * Montgomery modular multiplication
        * out: z = (x * y) / 2^256 mod m
        */
        static void montgomeryMul(uint32_t z[8], const uint32_t x[8], const uint32_t y[8], const ModulusContext *ctx)
        {
            // Algorithm 14.36 in Handbook of Applied Cryptography
            uint32_t m_prime {ctx->negModInverse};
            uint32_t a[9];

            for (uint_fast8_t i = 0; i < 9; i++)
            {
                a[i] = 0;
            }

            for (uint_fast8_t i = 0; i < 8; i++)
            {
                uint32_t u {(a[0] + x[i] * y[0]) * m_prime};
                // a = (a + x[i] * y + u * m) div b
                uint32_t c {multiplyAccumulate288(a, x[i], y)};

                c += multiplyAccumulate288(a, u, ctx->modulus);
                bigIntRightShift32(a, c);
            }

            uint32_t carry_add  {a[8]};
            uint32_t carry_sub  {bigIntSub(z, a, ctx->modulus)};
            uint32_t use_sub    {carry_add | (1 - carry_sub)};

            bigIntCondAssign(z, a, 1 - use_sub);
        }

        static void montgomeryMulP(uint32_t z[8], const uint32_t x[8], const uint32_t y[8])
        {
            montgomeryMul(z, x, y, &CONTEXT_P);
        }

        /*
        * In-place conversion to Montgomery form
        * out: z_out = z_in * 2^256 mod m
        */
        static void montgomeryEncode(uint32_t z[8], const ModulusContext *ctx)
        {
            montgomeryMul(z, z, ctx->R2, ctx);
        }

        /*
        * In-place conversion from Montgomery form
        * out: z_out = z_in / 2^256 mod m
        */
        static void montgomeryDecode(uint32_t z[8], const ModulusContext *ctx)
        {
            uint32_t one[8];

            bigIntSet32(one, 1);
            montgomeryMul(z, z, one, ctx);
        }

        /*
        * Set to 32-bit value in Montgomery domain
        */
        static void montgomerySet32(uint32_t z[8], uint32_t x, const ModulusContext *ctx)
        {
            bigIntSet32(z, x);
            montgomeryEncode(z, ctx);
        }

        /*
        * Modular inversion in Montgomery form
        * out: z = x^-1 * 2^512 mod m
        */
        static void montgomeryInv(uint32_t z[8], const uint32_t x[8], const ModulusContext *ctx)
        {
            // Fermat's little theorem: x^-1 = x^(m-2).
            uint32_t bitval[8];

            bigIntCondAssign(bitval, x, 1);

            montgomerySet32(z, 1, ctx);

            uint_fast8_t    i       {0};
            uint32_t        limb    {ctx->modulus[i] - 2};

            while (1)
            {
                for (uint_fast8_t j = 0; j < 32; j++)
                {
                    if ((limb & 1) != 0)
                    {
                        montgomeryMul(z, z, bitval, ctx);
                    }
                    montgomeryMul(bitval, bitval, bitval, ctx);
                    limb >>= 1;
                }

                if (i == 7)
                {
                    break;
                }
                i++;
                limb = ctx->modulus[i];
            }
        }

        /*
        * Import modular integer from bytes to Montgomery domain
        */
        static int montgomeryFromBytes(uint32_t z[8], const uint8_t p[32], const ModulusContext *ctx)
        {
            bigIntFromBytes(z, p);

            uint32_t t[8];
            uint32_t lt_m {bigIntSub(t, z, ctx->modulus)};

            if (lt_m != 1)
            {
                return FAIL;
            }

            montgomeryEncode(z, ctx);

            return SUCCESS;
        }

        /*
        * Export modular integer from Montgomery domain to bytes
        */
        static void montgomeryToBytes(uint8_t p[32], const uint32_t z[8], const ModulusContext *ctx)
        {
            uint32_t zi[8];

            bigIntCondAssign(zi, z, 1);
            montgomeryDecode(zi, ctx);
            bigIntToBytes(p, zi);
        }

        // --------------------------------------------------------------------------
        // Elliptic Curve Point Arithmetic
        // --------------------------------------------------------------------------

        /*
        * Check if point is on curve (y^2 = x^3 - 3x + b)
        */
        static uint32_t curvePointCheck(const uint32_t x[8], const uint32_t y[8])
        {
            uint32_t lhs[8], rhs[8];

            // lhs = y^2
            montgomeryMulP(lhs, y, y);

            // rhs = x^3 - 3x + b
            montgomeryMulP(rhs, x,   x);                            // x^2
            montgomeryMulP(rhs, rhs, x);                            // x^3
            for (uint_fast8_t i = 0; i < 3; i++)
            {
                modSubP(rhs, rhs, x);                               // x^3 - 3x
            }
            modAddP(rhs, rhs, CURVE_B_MONTGOMERY);                  // x^3 - 3x + b

            return (0 == bigIntCmpEq(lhs, rhs)) ? SUCCESS : FAIL;
        }

        /*
        * Convert Jacobian (x:y:z) to Affine (x:y)
        * x_out = x_in / z^2, y_out = y_in / z^3
        */
        static void curvePointToAffine(uint32_t x[8], uint32_t y[8], uint32_t z[8])
        {
            uint32_t t[8];

            montgomeryInv(z, z, &CONTEXT_P);                        // z = z^-1

            montgomeryMulP(t, z, z);                                // t = z^-2
            montgomeryMulP(x, x, t);                                // x = x * z^-2

            montgomeryMulP(t, t, z);                                // t = z^-3
            montgomeryMulP(y, y, t);                                // y = y * z^-3
        }

        /*
        * Point doubling in Jacobian coordinates
        * P_out = 2 * P_in
        */
        static void curvePointDouble(uint32_t x[8], uint32_t y[8], uint32_t z[8])
        {
            // Formula 6 from [CMO98]
            uint32_t m[8], s[8], u[8];

            // m = 3 * x^2 + a * z^4
            montgomeryMulP(s, z, z);
            modAddP(m, x, s);
            modSubP(u, x, s);
            montgomeryMulP(s, m, u);
            modAddP(m, s, s);
            modAddP(m, m, s);

            // s = 4 * x * y^2
            montgomeryMulP(u, y, y);
            modAddP(u, u, u);
            montgomeryMulP(s, x, u);
            modAddP(s, s, s);

            // u = 8 * y^4
            montgomeryMulP(u, u, u);
            modAddP(u, u, u);

            // x3 = m^2 - 2 * s
            montgomeryMulP(x, m, m);
            modSubP(x, x, s);
            modSubP(x, x, s);

            // z3 = 2 * y * z
            montgomeryMulP(z, y, z);
            modAddP(z, z, z);

            // y3 = m * (s - x3) - u
            modSubP(y, s, x);
            montgomeryMulP(y, y, m);
            modSubP(y, y, u);
        }

        /*
        * Point addition (Jacobian + Affine)
        * P_out = P_in + Q
        */
        static void curvePointAdd(uint32_t x1[8], uint32_t y1[8], uint32_t z1[8], const uint32_t x2[8], const uint32_t y2[8])
        {
            // Formula 5 from [CMO98] (Mixed coordinates)
            uint32_t t1[8], t2[8], t3[8];

            // u2 = x2 * z1^2
            montgomeryMulP(t1, z1, z1);
            montgomeryMulP(t2, t1, z1);
            montgomeryMulP(t1, t1, x2);

            // s2 = y2 * z1^3
            montgomeryMulP(t2, t2, y2);

            // h = u2 - x1
            modSubP(t1, t1, x1);

            // r = s2 - y1
            modSubP(t2, t2, y1);

            // z3 = z1 * h
            montgomeryMulP(z1, z1, t1);

            // h^3 and h^2
            montgomeryMulP(t3, t1, t1); // t3 = h^2
            montgomeryMulP(t1, t3, t1); // t1 = h^3

            // x1 * h^2
            montgomeryMulP(t3, t3, x1);

            // x3 = r^2 - 2 * x1 * h^2 - h^3
            montgomeryMulP(x1, t2, t2);
            modSubP(x1, x1, t3);
            modSubP(x1, x1, t3);
            modSubP(x1, x1, t1);

            // y3 = r * (x1 * h^2 - x3) - y1 * h^3
            modSubP(t3, t3, x1);
            montgomeryMulP(t3, t3, t2);
            montgomeryMulP(t1, t1, y1);
            modSubP(y1, t3, t1);
        }

        /*
        * Safe Point Addition/Doubling (Side-channel resistant)
        */
        static void curvePointAddOrDouble(uint32_t x3[8], uint32_t y3[8], const uint32_t x1[8], const uint32_t y1[8], const uint32_t x2[8], const uint32_t y2[8])
        {
            uint32_t z3[8];

            bigIntCondAssign(x3, x1, 1);
            bigIntCondAssign(y3, y1, 1);
            montgomerySet32(z3, 1, &CONTEXT_P);

            if (bigIntCmpEq(x1, x2) != 0)
            {
                // P != +- Q -> generic addition
                curvePointAdd(x3, y3, z3, x2, y2);
                curvePointToAffine(x3, y3, z3);
            } else if (bigIntCmpEq(y1, y2) == 0)
            {
                // P == Q -> double
                curvePointDouble(x3, y3, z3);
                curvePointToAffine(x3, y3, z3);
            } else
            {
                // P == -Q -> zero
                montgomerySet32(x3, 0, &CONTEXT_P);
                montgomerySet32(y3, 0, &CONTEXT_P);
            }
        }

        static int pointFromBytes(uint32_t x[8], uint32_t y[8], const uint8_t p[LENGTH_PUBLIC_KEY])
        {
            int result {montgomeryFromBytes(x, p, &CONTEXT_P)};

            if (SUCCESS != result)
            {
                return result;
            }

            result = montgomeryFromBytes(y, p + 32, &CONTEXT_P);
            if (SUCCESS != result)
            {
                return result;
            }

            return (int)curvePointCheck(x, y);
        }

        static void pointToBytes(uint8_t p[LENGTH_PUBLIC_KEY], const uint32_t x[8], const uint32_t y[8])
        {
            montgomeryToBytes(p,      x, &CONTEXT_P);
            montgomeryToBytes(p + 32, y, &CONTEXT_P);
        }

        /*
        * Scalar Multiplication (s * P)
        * Uses a Montgomery Ladder for side-channel resistance.
        */
        static void multiplyPointByScalar(uint32_t rx[8], uint32_t ry[8], const uint32_t px[8], const uint32_t py[8], const uint32_t s[8])
        {
            uint32_t sOdd[8], pyNeg[8], pyUse[8], rz[8];

            // Make s odd: sOdd = s if s is odd, else sOdd = n - s.
            bigIntSub(sOdd, CONTEXT_N.modulus, s);
            uint32_t negate {~s[0] & 1};
            bigIntCondAssign(sOdd, s, 1 - negate);

            // Compute -py
            bigIntSet32(pyUse, 0);
            modSubP(pyNeg, pyUse, py);

            // Init R = P or -P
            bigIntCondAssign(rx, px, 1);
            bigIntCondAssign(ry, py, 1);
            montgomerySet32(rz, 1, &CONTEXT_P);
            bigIntCondAssign(ry, pyNeg, negate);

            // Montgomery Ladder
            for (uint_fast8_t i = 255; i > 0; i--)
            {
                uint32_t bit {(sOdd[i / 32] >> i % 32) & 1};

                bigIntCondAssign(pyUse, py, bit ^ negate);
                bigIntCondAssign(pyUse, pyNeg, (1 - bit) ^ negate);

                curvePointDouble(rx, ry, rz);
                curvePointAdd(rx, ry, rz, px, pyUse);
            }

            curvePointToAffine(rx, ry, rz);
        }

        static int scalarFromBytes(uint32_t s[8], const uint8_t p[32])
        {
            bigIntFromBytes(s, p);

            uint32_t r[8];
            uint32_t lt_n {bigIntSub(r, s, CONTEXT_N.modulus)};

            bigIntSet32(r, 1);

            uint32_t lt_1 {bigIntSub(r, s, r)};

            return (lt_n && !lt_1) ? SUCCESS : FAIL;
        }

        static int generateScalarAndPoint(uint8_t sbytes[32], uint32_t s[8], uint32_t x[8], uint32_t y[8])
        {
            int             result;
            uint_fast8_t    retry   {0};

            do
            {
                if (retry++ >= 4)
                {
                    return FAIL;
                }

                fillRandom(sbytes);
                result = scalarFromBytes(s, sbytes);
            } while (SUCCESS != result);

            multiplyPointByScalar(x, y, GENERATOR_X, GENERATOR_Y, s);

            return SUCCESS;
        }

        // --------------------------------------------------------------------------
        // ECDSA Helper Functions
        // --------------------------------------------------------------------------

        static void ecdsaModN(uint32_t x[8])
        {
            uint32_t t[8];
            uint32_t c {bigIntSub(t, x, CONTEXT_N.modulus)};

            bigIntCondAssign(x, t, 1 - c);
        }

        static void ecdsaHashToInteger(uint32_t z[8], const uint8_t *h, size_t hlen)
        {
            if (hlen < 32)
            {
                uint8_t p[32];
                for (uint_fast8_t i = 0; i < 32; i++)
                {
                    p[i] = 0;
                }
                for (uint_fast8_t i = 0; i < hlen; i++)
                {
                    p[32 - hlen + i] = h[i];
                }
                bigIntFromBytes(z, p);
            } else
            {
                bigIntFromBytes(z, h);
            }

            ecdsaModN(z);
            montgomeryEncode(z, &CONTEXT_N);
        }
    } // Anonymous namespace

    // --------------------------------------------------------------------------
    // Public API Implementation
    // --------------------------------------------------------------------------

    void registerRandomFunction(RandomFunction func)
    {
        if (nullptr != func)
        {
            rngFunc = func;
        }
    }

    uint8_t generateKeyPair(uint8_t out_privateKey[LENGTH_PRIVATE_KEY], uint8_t out_publicKey[LENGTH_PUBLIC_KEY])
    {
        uint32_t s[8], x[8], y[8];
        int result {generateScalarAndPoint(out_privateKey, s, x, y)};

        secureZero(s, sizeof s);
        if (SUCCESS != result)
        {
            return FAIL;
        }

        pointToBytes(out_publicKey, x, y);

        return SUCCESS;
    }

    uint8_t computeSharedSecret(uint8_t out_secret[LENGTH_SECRET], const uint8_t in_privateKey[LENGTH_PRIVATE_KEY], const uint8_t in_peerPublicKey[LENGTH_PUBLIC_KEY])
    {
        uint32_t s[8], px[8], py[8], x[8], y[8];
        uint8_t result {(uint8_t)scalarFromBytes(s, in_privateKey)};

        if (SUCCESS != result)
        {
            result = INVALID_PRIVKEY;
            goto cleanup;
        }

        result = (uint8_t) pointFromBytes(px, py, in_peerPublicKey);
        if (SUCCESS != result)
        {
            result = INVALID_PUBKEY;
            goto cleanup;
        }

        multiplyPointByScalar(x, y, px, py, s);
        montgomeryToBytes(out_secret, x, &CONTEXT_P);

    cleanup:
        secureZero(s, sizeof s);

        return result;
    }

    uint8_t sign(uint8_t out_signature[LENGTH_SIGNATURE], const uint8_t in_privateKey[LENGTH_PRIVATE_KEY], const uint8_t *in_hash, size_t hashLen)
    {
        // Ephemeral key k, r coordinate, hash integer e, private key d
        uint32_t r_coord[8], k_scalar[8], e_hash[8], d_scalar[8];

        uint8_t *k_bytes {(uint8_t *) d_scalar};                    // reuse buffer temporarily
        int result {generateScalarAndPoint(k_bytes, k_scalar, r_coord, e_hash)}; 
        
        if (SUCCESS != result) return FAIL;

        montgomeryEncode(k_scalar, &CONTEXT_N);

        // 2. Convert r coordinate to integer and reduce mod n
        montgomeryDecode(r_coord, &CONTEXT_P);
        ecdsaModN(r_coord);

        if (bigIntCmpZero(r_coord) == 0) return FAIL;

        bigIntToBytes(out_signature, r_coord);                      // Store 'r' part of signature
        montgomeryEncode(r_coord, &CONTEXT_N);

        // 5. Derive integer from hash
        ecdsaHashToInteger(e_hash, in_hash, hashLen);

        // 6. Compute s = k^-1 * (e + r * d)
        result = scalarFromBytes(d_scalar, in_privateKey);

        if (SUCCESS != result) return INVALID_PRIVKEY;
        
        montgomeryEncode(d_scalar, &CONTEXT_N);

        montgomeryInv(k_scalar, k_scalar, &CONTEXT_N);              // k = k^-1
        montgomeryMul(d_scalar, r_coord, d_scalar, &CONTEXT_N);     // d = r * d
        modAdd(d_scalar, e_hash, d_scalar, &CONTEXT_N);             // d = e + r * d
        montgomeryMul(d_scalar, k_scalar, d_scalar, &CONTEXT_N);    // d = k^-1 * (e + r * d)
        secureZero(k_scalar, sizeof k_scalar);

        // 7. Output s
        if (bigIntCmpZero(d_scalar) == 0)
        {
            bigIntToBytes(out_signature, d_scalar);                 // wipe r
            return FAIL;
        }
        montgomeryToBytes(out_signature + 32, d_scalar, &CONTEXT_N);

        return SUCCESS;
    }

    uint8_t verify(const uint8_t in_signature[LENGTH_SIGNATURE], const uint8_t in_publicKey[LENGTH_PUBLIC_KEY], const uint8_t *in_hash, size_t hashLen)
    {
        uint32_t    r[8], s[8];
        int         result {scalarFromBytes(r, in_signature)};

        if (SUCCESS != result)
        {
            return INVALID_SIGNATURE;
        }
        
        result = scalarFromBytes(s, in_signature + 32);
        if (SUCCESS != result)
        {
            return INVALID_SIGNATURE;
        }

        uint32_t e[8];

        ecdsaHashToInteger(e, in_hash, hashLen);

        // Compute u1 = e * s^-1 and u2 = r * s^-1
        uint32_t u1[8], u2[8];

        montgomeryEncode(s, &CONTEXT_N);
        montgomeryInv(s, s, &CONTEXT_N);
        
        montgomeryMul(u1, e, s, &CONTEXT_N);
        montgomeryDecode(u1, &CONTEXT_N);

        bigIntCondAssign(u2, r, 1);
        montgomeryEncode(u2, &CONTEXT_N);
        montgomeryMul(u2, u2, s, &CONTEXT_N);
        montgomeryDecode(u2, &CONTEXT_N);

        // Compute R = u1*G + u2*Q
        uint32_t px[8], py[8];

        result = pointFromBytes(px, py, in_publicKey);
        if (SUCCESS != result)
        {
            return INVALID_PUBKEY;
        }

        multiplyPointByScalar(e, s, px, py, u2);                            // reusing e,s as temp storage for R2 point

        if (bigIntCmpZero(u1) == 0)
        {
            bigIntCondAssign(u1, e, 1);                                     // u1 is 0, so result is just u2*Q (stored in e,s)
        } else
        {
            multiplyPointByScalar(px, py, GENERATOR_X, GENERATOR_Y, u1);    // R1 = u1*G
            curvePointAddOrDouble(u1, u2, px, py, e, s);
        }

        // Verify x-coordinate of R matches r
        montgomeryDecode(u1, &CONTEXT_P);
        ecdsaModN(u1);

        uint32_t diff {bigIntCmpEq(u1, r)};

        return (0 == diff) ? SUCCESS : INVALID_SIGNATURE;
    }
}
