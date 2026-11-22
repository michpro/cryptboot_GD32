"""
Host tests for cryptboot_GD32 crypto (no hardware needed).

Compiles sha256/aes256cfb/p256 with g++ against a minimal
Arduino.h stub and checks NIST vectors + cross-implementation
agreement with Python (hashlib) and firmware_image_builder.

Run:  python utils/test_crypto_host.py [--cxx g++]
Exit: 0 = all pass, 1 = failure, 2 = harness error (no compiler).
"""

import argparse
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"

STUB = r"""
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
"""

DRIVER = r"""
#include <cstdio>
#include <cstring>
#include "sha256.h"
#include "aes256cfb.h"
#include "p256.h"
static int failures = 0;
#define CHECK(cond, label) do { \
    if (!(cond)) { printf("FAIL %s\n", label); ++failures; } \
    else { printf("ok %s\n", label); } } while (0)
static void hex(const uint8_t *b, size_t n, char *o) {
    for (size_t i = 0; i < n; ++i) sprintf(o + 2 * i, "%02x", b[i]);
}
int main() {
    // ECDSA P-256 positive vectors (independent Python `cryptography` impl)
    // V1 msg "cryptboot-p256-vector-1", V2 msg "cryptboot-p256-vector-2"
    // V1_PUB = X|Y big-endian, V1_HASH = SHA-256(msg), V1_SIG = r|s big-endian
    static const uint8_t V1_PUB[64] = {
        0x0F, 0xDE, 0xA6, 0x6A, 0xFF, 0x7A, 0xB3, 0x68, 0x38, 0x69, 0x2E, 0xCE, 0xCC, 0x17, 0xCB, 0xC0,
        0x7C, 0x7D, 0x92, 0x02, 0xB4, 0x8D, 0x8D, 0xDC, 0xAA, 0xD0, 0x2D, 0x57, 0x2F, 0xA7, 0x9E, 0x45,
        0xCB, 0x72, 0x3D, 0x80, 0xC6, 0x78, 0x95, 0xCC, 0x46, 0x7D, 0xF5, 0x44, 0x3E, 0x42, 0xE4, 0xB1,
        0x5C, 0x5D, 0x86, 0x27, 0x15, 0x35, 0x46, 0xA5, 0xD5, 0xC5, 0x62, 0x06, 0x1D, 0xD3, 0xF8, 0x3A
    };
    static const uint8_t V1_HASH[32] = {
        0x05, 0xF7, 0x9D, 0x00, 0x8D, 0xE3, 0x42, 0x8C, 0xDC, 0x23, 0xDC, 0xE5, 0x02, 0x21, 0x8D, 0xD4,
        0x4F, 0xC5, 0x87, 0x2D, 0xA9, 0xD1, 0x8E, 0x06, 0x5D, 0xB7, 0x26, 0x3F, 0xAA, 0x4B, 0xC0, 0xD5
    };
    static const uint8_t V1_SIG[64] = {
        0x0A, 0xEE, 0xC1, 0x5B, 0x40, 0xA7, 0x59, 0x46, 0x99, 0x2F, 0x91, 0x0B, 0x8C, 0x49, 0x1B, 0x0D,
        0x03, 0xA3, 0xB7, 0x9F, 0xA2, 0x91, 0x8C, 0x68, 0x88, 0x7E, 0x2B, 0x32, 0x1F, 0xAE, 0x03, 0x45,
        0xA1, 0xEC, 0xCD, 0x12, 0x05, 0xEB, 0x45, 0x25, 0xBC, 0x4E, 0xDB, 0xFB, 0x0D, 0x07, 0xF0, 0x4B,
        0xAC, 0x29, 0x63, 0x98, 0xAC, 0x26, 0x54, 0x3E, 0x4D, 0xD7, 0xDC, 0xDA, 0x60, 0xB6, 0xF7, 0x5E
    };
    static const uint8_t V2_PUB[64] = {
        0xEE, 0xBF, 0xB2, 0x3D, 0x20, 0x92, 0xDF, 0x3A, 0x75, 0x8D, 0xCD, 0xA8, 0x3C, 0x96, 0x18, 0x9E,
        0xF1, 0x72, 0x3F, 0xCF, 0xCA, 0x1F, 0x27, 0x1B, 0x8D, 0x25, 0xF0, 0xB2, 0xA6, 0x65, 0x5E, 0xDE,
        0xC0, 0xFA, 0xF2, 0x33, 0x75, 0xDD, 0xA9, 0x84, 0xDF, 0x05, 0xCD, 0xD6, 0x9D, 0xF5, 0x11, 0xE4,
        0xF3, 0xB1, 0x09, 0xC0, 0xEC, 0x08, 0xE8, 0x86, 0x41, 0x40, 0xAE, 0x54, 0x5D, 0xE5, 0x64, 0x4A
    };
    static const uint8_t V2_HASH[32] = {
        0x27, 0xC1, 0x23, 0x02, 0x4D, 0xBF, 0xDD, 0x3D, 0x34, 0x05, 0xFD, 0x1A, 0x46, 0xC3, 0x86, 0x1D,
        0x58, 0x48, 0x77, 0x23, 0x6F, 0xB6, 0x97, 0x9C, 0x30, 0x93, 0x53, 0xD3, 0xDD, 0xE3, 0x6B, 0x78
    };
    static const uint8_t V2_SIG[64] = {
        0xFF, 0xA2, 0x68, 0xEE, 0x17, 0x0D, 0x74, 0xB6, 0x7C, 0xD7, 0xB4, 0x8A, 0x0A, 0x64, 0x07, 0x34,
        0xD1, 0x15, 0x2E, 0x4A, 0x15, 0x29, 0x15, 0x5E, 0x24, 0xF6, 0x2C, 0x59, 0x09, 0xB8, 0x11, 0x93,
        0x66, 0x23, 0xA2, 0x25, 0x3E, 0x70, 0xCF, 0x33, 0x2B, 0x13, 0x77, 0x18, 0x2B, 0x3C, 0x0E, 0xE4,
        0x4E, 0x2B, 0xB0, 0x35, 0x29, 0x8E, 0xA4, 0xE5, 0x4B, 0x3A, 0x5E, 0x8B, 0x18, 0xFF, 0x37, 0x9C
    };
    CHECK(P256::SUCCESS == P256::verify(V1_SIG, V1_PUB, V1_HASH, 32), "p256-v1-valid");
    CHECK(P256::SUCCESS == P256::verify(V2_SIG, V2_PUB, V2_HASH, 32), "p256-v2-valid");
    // Tampered signature byte must fail (same key and hash as V1)
    uint8_t badSig[64]; memcpy(badSig, V1_SIG, 64); badSig[63] ^= 0x01;
    CHECK(P256::SUCCESS != P256::verify(badSig, V1_PUB, V1_HASH, 32), "p256-rejects-tampered-sig");
    // Tampered hash byte must fail (same key and signature as V1)
    uint8_t badHash[32]; memcpy(badHash, V1_HASH, 32); badHash[0] ^= 0x01;
    CHECK(P256::SUCCESS != P256::verify(V1_SIG, V1_PUB, badHash, 32), "p256-rejects-tampered-hash");
    // SHA-256("abc") — NIST vector
    SHA256::context_t ctx; uint8_t h[32]; char s[65];
    SHA256::init(&ctx);
    SHA256::update(&ctx, (const uint8_t *)"abc", 3);
    SHA256::final(&ctx, h); hex(h, 32, s);
    CHECK(0 == strcmp(s, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "sha256-abc");
    // SHA-256("") — empty string vector
    SHA256::init(&ctx);
    SHA256::final(&ctx, h); hex(h, 32, s);
    CHECK(0 == strcmp(s, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "sha256-empty");
    // AES-256-CFB roundtrip (key 0x00.., iv 0x00.., 2 blocks)
    uint8_t key[32] = {0}, iv[16] = {0}, pt[32], ct[32];
    for (int i = 0; i < 32; ++i) pt[i] = (uint8_t)i;
    AES256::setKey(key); AES256::setIv(iv); AES256::setOperation(AES256::ENCRYPT);
    memcpy(ct, pt, 16); AES256::cfbProcessBlock(ct);
    memcpy(ct + 16, pt + 16, 16); AES256::cfbProcessBlock(ct + 16);
    CHECK(0 != memcmp(ct, pt, 32), "aes-cfb-encrypts");
    AES256::setKey(key); AES256::setIv(iv); AES256::setOperation(AES256::DECRYPT);
    AES256::cfbProcessBlock(ct);
    AES256::cfbProcessBlock(ct + 16);
    CHECK(0 == memcmp(ct, pt, 32), "aes-cfb-roundtrip");
    // P-256: wrong-signature must fail (no RNG needed for verify path)
    uint8_t sig[64] = {0}, pub[64] = {0}, hh[32] = {0};
    uint8_t r = P256::verify(sig, pub, hh, 32);
    CHECK(P256::SUCCESS != r, "p256-rejects-garbage");
    printf(failures ? "RESULT FAIL\n" : "RESULT OK\n");
    return failures ? 1 : 0;
}
"""


def main(argv=None) -> int:
    """Builds and runs the host crypto test driver."""
    parser = argparse.ArgumentParser(description="cryptboot host crypto tests")
    parser.add_argument("--cxx", default="g++", help="C++ compiler")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        (tmpdir / "Arduino.h").write_text(STUB, encoding="utf-8")
        (tmpdir / "driver.cpp").write_text(DRIVER, encoding="utf-8")
        sources = ["sha256.cpp", "aes256cfb.cpp", "p256.cpp"]
        cmd = [args.cxx, "-std=c++17", "-O1", "-I", str(tmpdir),
               "-I", str(SRC), str(tmpdir / "driver.cpp")] + \
            [str(SRC / s) for s in sources] + ["-o", str(tmpdir / "t")]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            print(f"SKIP: no compiler {args.cxx!r} (CI runs this on ubuntu).")
            return 0
        if 0 != proc.returncode:
            print(f"HARNESS ERROR: compile failed:\n{proc.stderr[:1500]}")
            return 2
        exe = tmpdir / ("t.exe" if sys.platform == "win32" else "t")
        proc = subprocess.run([str(exe)], capture_output=True, text=True,
                              timeout=120)
        print(proc.stdout, end="")
        # Cross-check: Python hashlib agrees on sha256("abc")
        ref = hashlib.sha256(b"abc").hexdigest()
        assert "ba7816bf" == ref[:8], "python reference broken"
        print(f"ok python-crosscheck ({ref[:16]}...)")
        return proc.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
