/**
 * @file p256.h
 * @brief Optimized implementation of NIST P-256 (secp256r1) Elliptic Curve Cryptography.
 *
 * This library provides ECDH (Key Exchange) and ECDSA (Signing/Verification)
 * on the P-256 curve. It is optimized for 32-bit embedded systems (Arduino).
 *
 * @note    This implementation uses Montgomery multiplication for field arithmetic.
 * @warning You MUST attach a cryptographically secure random number generator (CSPRNG)
 * via registerRandomFunction() before generating keys or signing.
 * 
 * @copyright SPDX-FileCopyrightText: Copyright 2025-2026 by Michal Protasowicki
 * @license SPDX-License-Identifier: MIT license
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

namespace P256
{
    /**
     * @brief Function pointer type for the Random Number Generator.
     * @return A random 32-bit integer.
     */
    typedef long (*RandomFunction)(void);

    /**
     * @brief Operation result status codes.
     */
    typedef enum : uint8_t
    {
        FAIL                = 0,    ///< Generic failure (e.g., point not on curve, RNG failure).
        INVALID_PUBKEY,             ///< Public key is invalid or not on the curve.
        INVALID_PRIVKEY,            ///< Private key is invalid (e.g., out of range).
        INVALID_SIGNATURE,          ///< ECDSA verification failed.
        SUCCESS                     ///< Operation successful.
    } result_t;

    // Buffer length constants (in bytes)
    static const uint8_t LENGTH_SIGNATURE   {64};                   ///< r (32 bytes) + s (32 bytes)
    static const uint8_t LENGTH_PUBLIC_KEY  {64};                   ///< X (32 bytes) + Y (32 bytes). Uncompressed.
    static const uint8_t LENGTH_PRIVATE_KEY {32};                   ///< Big-endian integer.
    static const uint8_t LENGTH_SECRET      {32};                   ///< Shared secret (ECDH result).

    /**
     * @brief Registers the Random Number Generator function.
     * This is REQUIRED for security. If not set, operations requiring randomness
     * (Key Generation, Signing) will rely on a static filler and will NOT be secure.
     *
     * @param func Pointer to a function returning a random 32-bit integer.
     */
    void registerRandomFunction(RandomFunction func);

    /**
     * @brief Generates a new P-256 Private/Public key pair.
     *
     * @param[out] out_privateKey Buffer (32 bytes) to store the generated private scalar.
     * @param[out] out_publicKey  Buffer (64 bytes) to store the generated public point (X|Y).
     * @return SUCCESS on success, FAIL if RNG fails or internal math error.
     */
    uint8_t generateKeyPair(uint8_t out_privateKey[LENGTH_PRIVATE_KEY], 
                            uint8_t out_publicKey[LENGTH_PUBLIC_KEY]);

    /**
     * @brief Computes an ECDH Shared Secret.
     * Performs the Diffie-Hellman multiplication: Secret = PrivateKey_A * PublicKey_B.
     * @param[out] out_secret       Buffer (32 bytes) to store the resulting X coordinate of the shared point.
     * @param[in]  in_privateKey    My private key (32 bytes).
     * @param[in]  in_peerPublicKey The peer's public key (64 bytes).
     * @return SUCCESS, INVALID_PRIVKEY, or INVALID_PUBKEY.
     */
    uint8_t computeSharedSecret(uint8_t out_secret[LENGTH_SECRET], 
                                const uint8_t in_privateKey[LENGTH_PRIVATE_KEY], 
                                const uint8_t in_peerPublicKey[LENGTH_PUBLIC_KEY]);

    /**
     * @brief Generates an ECDSA Signature for a given message hash.
     * @warning The input must be a cryptographic HASH of the message, not the message itself.
     * @note This function requires a valid RNG to generate the ephemeral key 'k'.
     *
     * @param[out] out_signature  Buffer (64 bytes) to store the signature (r|s).
     * @param[in]  in_privateKey  The signer's private key (32 bytes).
     * @param[in]  in_hash        The hash of the data to sign.
     * @param[in]  hashLen        Length of the hash in bytes (usually 32 for SHA-256).
     * @return SUCCESS, FAIL (RNG error), or INVALID_PRIVKEY.
     */
    uint8_t sign(uint8_t out_signature[LENGTH_SIGNATURE], 
                 const uint8_t in_privateKey[LENGTH_PRIVATE_KEY], 
                 const uint8_t *in_hash, 
                 size_t hashLen);

    /**
     * @brief Verifies an ECDSA Signature.
     *
     * @param[in] in_signature Buffer (64 bytes) containing the signature (r|s).
     * @param[in] in_publicKey The signer's public key (64 bytes).
     * @param[in] in_hash      The hash of the original data.
     * @param[in] hashLen      Length of the hash in bytes.
     * @return SUCCESS if valid, INVALID_SIGNATURE or INVALID_PUBKEY otherwise.
     */
    uint8_t verify(const uint8_t in_signature[LENGTH_SIGNATURE], 
                   const uint8_t in_publicKey[LENGTH_PUBLIC_KEY], 
                   const uint8_t *in_hash, 
                   size_t hashLen);
}
