# Production Release Procedure — cryptboot_GD32 + signed application

**Scope**: this repository (cryptboot_GD32). The consumer application delivers
the signed image over its own transport (UART, CAN/VSCP, MODBUS, USB, …);
this procedure covers key ceremony, image building, flashing, and first-boot
verification on the bootloader side.

**Principle**: the bootloader is immutable OTA — no self-update path exists.
Any layout change (`APP_OFFSET`, NV, staging) means a new bootloader via SWD.

---

## 0. One-time key ceremony (offline machine, never the dev laptop)

1. Generate the P-256 pair on an offline machine:
   `python firmware_image_builder.py --P256gen --privKeyPwd ask`
   → `bootloader_private_key.pem` (ENCRYPTED, password in vault) +
   `bootloader_public_key.h`.
2. Copy ONLY `bootloader_public_key.h` next to `src/declarations.h`.
   The `.pem` NEVER enters any repo, tree, backup, or chat
   (`.gitignore` already excludes `*.pem` + the header copy).
3. Record in the release log: key fingerprint (SHA-256 of the header file),
   date, custodian, vault location. Rotation = new ceremony + new header.

## 1. Production configuration (compile-time, verified before build)

| Symbol | Production value | Dev default | Where |
|---|---|---|---|
| `DEVICE_ID` | real target HW id (one per HW variant) | `0xFFFF` | `src/declarations.h` |
| `RDP_LEVEL` | `1` (build flag `-DRDP_LEVEL=1`) | `0` | `src/config.h` / build flag |
| `DOWNGRADE_ALLOWED` | `0` | `1` | `src/config.h` / build flag |
| `APPLICATION_CRC_CHECK` | `1` | `1` | `src/config.h` / build flag |
| `USE_LED` | `1` | `1` | `src/config.h` / build flag |
| `DUAL_BANK_FLASH` | target-dependent | `0` | `src/config.h` / build flag |

RDP-1 blocks SWD reads; recovery is mass-erase ONLY (destroys bootloader +
app + emulated EEPROM). The unbrick procedure must be on the bench before the
first RDP-1 unit ships. Timestamp resolution is one minute — two builds inside
the same minute share a timestamp; with `DOWNGRADE_ALLOWED=0` the second build
is rejected, so wait for the minute to roll over between release candidates.

## 2. CI build matrix

CI compiles all eight combinations of `RDP_LEVEL` (0/1), `DUAL_BANK_FLASH`
(0/1), and `DOWNGRADE_ALLOWED` (0/1); the 18 kB size gate applies to every
`.bin`. The forced dual-bank build exercises the larger code path on the
GD32F303CC target, but does not qualify dual-bank hardware behavior.

For production, use `RDP_LEVEL=1`, the `DUAL_BANK_FLASH` value matching the
actual target, and `DOWNGRADE_ALLOWED=0`. The other matrix builds are test
variants, not production images.

1. `utils/test_crypto_host.py` — NIST vectors + positive ECDSA vectors
   must pass (runs on CI Ubuntu; no compiler on Windows dev machine = SKIP).
2. Renode `run_boot.py --scenario all` — jump + error, 2/2.
3. `utils/test_naked_main.py` — checks the default build ELF.

## 3. Image building (signing machine = offline or access-controlled)

1. First image for virgin flash: `--file app.bin --devID <REAL_ID>` (cipher
   NONE, default key is 32× `0xFF` — this image travels ONLY over a trusted
   channel: SWD/OpenOCD or local UART, NEVER over an untrusted bus).
2. Rotate immediately: rebuild with `--cipher AES256 --key <OLD> --newKey
   <NEW>` so the field key differs from the all-`0xFF` starter; the new key
   lands encrypted in the header `newKey` field and in NV (`ID_CIPHER_KEY`).
3. Verify: `firmwareSize % 4 == 0`, `size <= APP_MAX_SIZE`, `version 0x11`,
   `deviceId` matches, timestamp newer than field units (unless first flash).
4. Name releases explicitly, e.g. `app-v2.3.0-devid42-20261117-1435.signed.bin`
   — NEVER ship a bare `*.signed.bin` from the repo root as a release.

## 4. Flashing

- **Provisioning (virgin / unbrick)**: OpenOCD full erase → program bootloader
  at `0x08000000` → program `.signed.bin` at staging `0x08020000` →
  `reset run` → bootloader verifies (ECDSA → decrypt → copy to `0x08005000` →
  NV + CRC) → app boots. Confirm `IWDG_SW = 1` (software watchdog) in option
  bytes at provisioning time.
- **Field update (app only)**: the consumer delivers the image to staging
  and reboots; the bootloader path is unchanged. A bootloader image is never
  accepted — only the application target is written.

## 5. First-boot verification (production unit)

1. App boots, VTOR at `0x08005000`, version register matches release.
2. `DEVICE_ID` gate: an image built for another id is rejected (spot-check
   with a wrong-`--devID` image on a sacrificial unit, expect refusal).
3. Downgrade attempt with an older timestamp is rejected
   (`DOWNGRADE_ALLOWED=0`).
4. RDP-1 unit: SWD read fails, SWD mass-erase still works (bench only).
5. Keep one RDP-0 golden unit per release for failure analysis.

## 6. What is NOT done

- No OTA of the bootloader. Frozen layout (GD32F303CC / 256 KB flash):
  `APP_OFFSET 0x5000`, NV at `APP_START − 2K` (`0x08004800`), staging at
  `FIRMWARE_STORE_BASE_ADDRESS` (flash base + `APP_STORE_OFFSET`, i.e. half
  of flash). The payload limit is `APP_MAX_SIZE`, not a page count — other
  flash sizes scale via `HALF_OF_FLASH` (see `src/declarations.h`).
- Private key never leaves the vault machine. No key in repo, mail, chat.
- First (all-`0xFF`-key) image never over an untrusted bus.
