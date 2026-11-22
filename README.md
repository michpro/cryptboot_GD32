- [cryptboot GD32](#cryptboot-gd32)
  - [🚀 Key Features](#-key-features)
  - [🛠️ Development Environment](#️-development-environment)
    - [Prerequisites](#prerequisites)
  - [📑 Application Requirements](#-application-requirements)
    - [Vector Table Relocation (`vtor_init`)](#vector-table-relocation-vtor_init)
    - [Vector Table Relocation](#vector-table-relocation)
    - [Customizing `boards.txt` for Easy Offset Selection](#customizing-boardstxt-for-easy-offset-selection)
    - [Building with Arduino CLI](#building-with-arduino-cli)
  - [🔄 Firmware Updates and Delivery](#-firmware-updates-and-delivery)
  - [💾 Flashing with OpenOCD](#-flashing-with-openocd)
    - [1. Read Flash Memory (Backup)](#1-read-flash-memory-backup)
    - [2. Erase Flash](#2-erase-flash)
    - [3. Upload Signed Application](#3-upload-signed-application)
  - [📦 Firmware Image Builder](#-firmware-image-builder)
    - [1. Generate Key Pair (Required for first-time use)](#1-generate-key-pair-required-for-first-time-use)
    - [2. Prepare Signed Image (No encryption)](#2-prepare-signed-image-no-encryption)
    - [3. Prepare Encrypted Image (AES-256)](#3-prepare-encrypted-image-aes-256)
  - [📄 License](#-license)
  - [Support](#support)

---

# cryptboot GD32

[![CI](https://github.com/michpro/cryptboot_GD32/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/michpro/cryptboot_GD32/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

`cryptboot GD32` is a secure bootloader designed for **GigaDevice GD32** microcontrollers. It ensures that only authorized, encrypted, and signed firmware images are executed on the hardware.



## 🚀 Key Features

* **Firmware Encryption & Signing:** Protects intellectual property and ensures firmware authenticity using the [`firmware_image_builder.py`](./firmware_image_builder/README.md) tool.
* **Readout Protection (RDP Level 1):** Optional production hardening — build with `-DRDP_LEVEL=1` to block external SWD reads after first boot. Internal FMC operations (app EEPROM emulation, OTA staging writes) are unaffected. Recovery from RDP-1 is mass-erase only. See [RELEASE-PROCEDURE.md](./RELEASE-PROCEDURE.md).
* **Prophylactic Watchdog Feeding:** The long flash loops (`isFirmwareSignatureOk`, `processFirmwareData`, `cleanStoredFirmware`) reload the FWDGT counter once per page. With FWDGT disabled (normal System Reset entry) the reload key is ignored by hardware; it keeps the bootloader alive if ever entered without a system reset or with hardware-watchdog option bytes. The start key is never written.
* **Verify-After-Write:** `Flash::writePage` reads the page back word-by-word before locking; a silent programming bit-flip is reported as failure so the caller's retry loop engages instead of hiding until the whole-image CRC.
* **Host Crypto Tests:** `utils/test_crypto_host.py` checks SHA-256 NIST vectors, AES-256-CFB roundtrip, and ECDSA P-256 positive vectors (independent Python `cryptography` implementation) plus tamper rejection. Runs in CI on Ubuntu.
* **Arduino Integration:** Optimized for development within the Arduino IDE using the [ArduinoCore-GD32](https://github.com/CommunityGD32Cores/ArduinoCore-GD32) project.
* **Vector Table Management:** Automated handling of application entry points via specialized constructor functions.



## 🛠️ Development Environment

The project is designed to work with the **Arduino ecosystem**.

### Prerequisites
1.  **Arduino Core:** Install [ArduinoCore-GD32](https://github.com/CommunityGD32Cores/ArduinoCore-GD32).
2.  **Python 3:** Required for the [`firmware_image_builder.py`](./firmware_image_builder/README.md) script (requires `cryptography` library).
3.  **OpenOCD:** Used for flashing and memory management.



## 📑 Application Requirements

### Vector Table Relocation (`vtor_init`)
Because the bootloader resides at the start of the flash memory, the user application must be linked to a specific offset (typically `0x08005000` [`20kB`]).

### Vector Table Relocation
Your application must relocate the Vector Table (VTOR) to its starting address in flash to ensure interrupts work correctly after the bootloader jumps to the application.
To achieve this, you **must** include the following function in your Arduino sketch. This uses the `constructor` attribute to ensure it executes before the main application logic starts.</br>
A complete example of how to achieve this using a constructor function can be found in the [Blink.ino](./utils/example_application/Blink/Blink.ino) file:

```cpp
#if defined(FLASH_OFFSET) && FLASH_OFFSET != 0
__attribute__((constructor(102))) void vtor_init()
{
    // Calculate the start address based on the flash base and defined offset
    constexpr uint32_t THIS_APP_START_ADDRESS {FLASH_BASE + (uint32_t)(FLASH_OFFSET)};

    SCB->VTOR = THIS_APP_START_ADDRESS;
    __DSB();
}
#endif
```

### Customizing `boards.txt` for Easy Offset Selection
To simplify the development process, it is highly recommended to replace the original `boards.txt` file in your Arduino Core installation with the custom [`boards.txt`](./utils/boards/boards.txt) provided in this repository.

By using this version of [`boards.txt`](./utils/boards/boards.txt), you gain a new menu item in the Arduino IDE: **"FLASH start offset"**. This allows you to select the correct application offset (e.g., `0x5000`) directly from the **"Tools"** menu, ensuring the code is compiled with the correct `FLASH_OFFSET` definition.

### Building with Arduino CLI
If you prefer using the command line, you can specify the flash offset during compilation by passing the build property:

```bash
arduino-cli compile --fqbn community_gd32:gd32:gd_generic_gd32f30x:pnum=GD32F303CC_GENERIC \
--build-property "build.flash_offset=0x5000" \
--build-property "build.extra_flags=-DFLASH_OFFSET=0x5000" \
./Blink.ino
```

## 🔄 Firmware Updates and Delivery

Since `cryptboot GD32` is a minimal secure bootloader that operates strictly on the flash memory, the responsibility for receiving and delivering new firmware images is best delegated to the **user application**.

This approach provides maximum flexibility:
* The application can use **any communication interface** available on the chip (UART, MODBUS, USB, CAN, LAN, etc.) to fetch the encrypted `.signed.bin` file.
* Once the new firmware is downloaded and stored in internal flash, the application simply triggers the bootloader update process.
* The **OpenOCD** method (shown in the Flashing section below) is typically used only for the **initial deployment** of the bootloader and the first application image. Subsequent updates are handled wirelessly or via the chosen industrial bus.



## 💾 Flashing with OpenOCD

Use the following commands to manage the flash memory of your GD32 device. These examples utilize the `openocd.exe` binary and scripts provided in the project.

### 1. Read Flash Memory (Backup)
To back up the existing firmware (e.g., 256KB from bank 0):
* **ST-Link:**
    ```bash
    .\bin\openocd.exe -s .\scripts -f interface/stlink.cfg -c "set CPUTAPID 0" -f target/stm32f1x.cfg -c "transport select hla_swd; init; reset halt; flash read_bank 0 firmware.bin 0 0x40000; reset; shutdown"
    ```
* **CMSIS-DAP:**
    ```bash
    .\bin\openocd.exe -s .\scripts -f interface/cmsis-dap.cfg -c "set CPUTAPID 0" -f target/stm32f1x.cfg -c "transport select swd; init; reset halt; flash read_bank 0 firmware.bin 0 0x40000; reset; shutdown"
    ```

### 2. Erase Flash
To perform a full or partial sector erase:
* **Full Erase (ST-Link):**
    ```bash
    .\bin\openocd.exe -s .\scripts -f interface/stlink.cfg -c "set CPUTAPID 0" -f target/stm32f1x.cfg -c "transport select hla_swd; flash init; init; reset halt; flash erase_sector 0 0 last; reset; shutdown"
    ```
* **Partial Erase (Sectors 9 to last via CMSIS-DAP):**
    ```bash
    .\bin\openocd.exe -s .\scripts -f interface/cmsis-dap.cfg -c "set CPUTAPID 0" -f target/stm32f1x.cfg -c "transport select swd; flash init; init; reset halt; flash erase_sector 0 9 last; reset; shutdown"
    ```
    _*Note: **Sector 9** is reserved for internal bootloader metadata, including the firmware CRC32 checksum, AES256 encryption key, timestamp, and firmware size. The user application itself is stored and executed starting from **Sector 10**._

> **Production configuration:** set a real `DEVICE_ID` (never ship `0xFFFF`), build with `-DRDP_LEVEL=1`, and set `DOWNGRADE_ALLOWED=0` (`src/config.h`). Keep the private key offline — only `bootloader_public_key.h` belongs next to the sources. Full ceremony in [RELEASE-PROCEDURE.md](./RELEASE-PROCEDURE.md).

### 3. Upload Signed Application
To upload your processed binary to the specific application offset (e.g., `0x08020000`):
* **Example for Blink:**
    ```bash
    .\bin\openocd.exe -s .\scripts -f interface/cmsis-dap.cfg -c "set CPUTAPID 0" -f target/stm32f1x.cfg -c "transport select swd; program Blink.ino.signed.bin 0x08020000; reset run; shutdown"
    ```
    _Note: The signed application **must** be located in the correct place in the flash memory (with the default bootloader settings, this is `0x08020000`). Then, if verification is successful, bootloader moves the application to the start address `0x08005000`._

_**Important Note on Debugger Interfaces:**_</br>
_In the commands listed above, depending on your hardware, you must adjust the interface and transport settings:_
* _For **CMSIS-DAP**: Use `-f interface/cmsis-dap.cfg` and `transport select swd`._
* _For **ST-Link**: Use `-f interface/stlink.cfg` and `transport select hla_swd`._


## 📦 Firmware Image Builder

The [`firmware_image_builder.py`](./firmware_image_builder/README.md) script is used to prepare binary firmware images. It handles SHA256 hashing, GD32-compatible hardware CRC32 calculation, AES-256 encryption, and ECDSA P-256 signing.

### 1. Generate Key Pair (Required for first-time use)
Before signing any firmware, you must generate your security keys:
```bash
python firmware_image_builder.py --P256gen
```
*This generates `bootloader_private_key.pem` (private key) and `bootloader_public_key.h` (public key to be included in the bootloader source).*

### 2. Prepare Signed Image (No encryption)
To sign a standard `.bin` file generated by the Arduino IDE:
```bash
python firmware_image_builder.py --file Blink.ino.bin
```
*Output: `Blink.ino.signed.bin` containing a 128-byte header with the digital signature.*

### 3. Prepare Encrypted Image (AES-256)
If your bootloader configuration requires encrypted firmware, provide a 32-byte hex key:
```bash
python firmware_image_builder.py --file Blink.ino.bin --cipher AES256 --key 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
```
*Note: The first firmware is encrypted with a default key consisting of a string of 32 0xFF numbers, and we provide the --newKey argument with a new AES256 key. That first image must travel over a trusted channel only (SWD/OpenOCD or local UART) — never over an untrusted bus — then rotate immediately, see [RELEASE-PROCEDURE.md](./RELEASE-PROCEDURE.md).*


## 📄 License
Copyright © 2025-2026 Michal Protasowicki

This software is released under the **MIT License**.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

## Support
If You find my projects interesting and You wanted to support my work, You can give me a cup of coffee or a keg of beer :)

[![PayPal Direct](https://badgen.net/badge/icon/Support%20me%20by%20PayPal?icon=kofi&label&scale=1.5&color=blue)](https://www.paypal.me/michpro)&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[![ko-fi](https://badgen.net/badge/icon/Support%20me%20on%20Ko-fi?icon=kofi&label&scale=1.5&color=red)](https://ko-fi.com/F1F24CEW1)
