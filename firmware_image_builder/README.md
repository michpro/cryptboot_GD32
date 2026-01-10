- [CryptBootGD32 Firmware Image Builder](#cryptbootgd32-firmware-image-builder)
  - [🛠️ Project Setup \& Installation](#️-project-setup--installation)
    - [Automated Installation](#automated-installation)
    - [🚀 Manual Activation](#-manual-activation)
  - [💡 Key Features](#-key-features)
  - [💻 Command Line Usage](#-command-line-usage)
    - [1. Generating a Key Pair](#1-generating-a-key-pair)
    - [2. Extracting Public Key](#2-extracting-public-key)
    - [3. Building a Signed Firmware (No Encryption)](#3-building-a-signed-firmware-no-encryption)
    - [4. Building an Encrypted and Signed Firmware](#4-building-an-encrypted-and-signed-firmware)
  - [🏗 Binary Image Structure](#-binary-image-structure)
  - [⚙️ Technical Implementation Details](#️-technical-implementation-details)
    - [Mode Bitfield Configuration](#mode-bitfield-configuration)
    - [Firmware Padding and Activation](#firmware-padding-and-activation)
    - [CRC32 Algorithm](#crc32-algorithm)
  - [⚠️ Troubleshooting](#️-troubleshooting)
  - [📄 License](#-license)
  - [Support](#support)

---

# CryptBootGD32 Firmware Image Builder

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

The `firmware_image_builder.py` is a tool designed to generate, encrypt, and sign firmware images compatible with the **CryptBootGD32** bootloader. It ensures firmware integrity and confidentiality for GD32-based microcontrollers using industry-standard cryptographic primitives.



## 🛠️ Project Setup & Installation

This project includes automated scripts to set up a Python virtual environment and install necessary dependencies.

### Automated Installation
1. **For Windows Users**:
   Run the `install.bat` file:
    ```bash
    install.bat
    ```
   *The script will check for Python, create a `.venv` if it doesn't exist, upgrade pip, and install dependencies from `requirements.txt`.*

2. **For Linux/macOS Users**:
   Grant execution permissions and run the script:
    ```bash
    chmod +x install.sh
    ./install.sh
    ```
   *The script verifies `python3`, creates the virtual environment using `venv`, upgrade pip, and installs the project requirements.*

### 🚀 Manual Activation
After installation, activate the virtual environment in every new terminal session:

* **Windows**:
    ```bash
    .\.venv\Scripts\activate
    ```
* **Linux / macOS**:
    ```bash
    source .venv/bin/activate
    ```
    *Once activated, your terminal prompt will usually show `(.venv)` at the beginning.*



## 💡 Key Features

* **GD32 Hardware-Compatible CRC32**: Implements a calculation mimicking the GD32 hardware acceleration unit (32-bit words, Little Endian).
* **Asymmetric Signing**: Uses **ECDSA P-256** with SHA-256 for authenticity.
* **Symmetric Encryption**: Supports **AES-256 in CFB mode**.
* **Key Management**: Tools for generating P-256 key pairs and exporting public keys to C-style headers.
* **Secure Key Distribution**: Capability to include an encrypted "New Key" in the firmware header.



## 💻 Command Line Usage

### 1. Generating a Key Pair
Generate a new ECDSA P-256 private key (PEM) and a public key header file:
```bash
python firmware_image_builder.py --P256gen --privKeyPwd ask
```
*Note: Using `ask` will prompt you to securely enter a password for the private key file.*

### 2. Extracting Public Key
Regenerate the `bootloader_public_key.h` from an existing private key:
```bash
python firmware_image_builder.py --pubKeyGet --privKeyPath path/to/key.pem --privKeyPwd ask
```

### 3. Building a Signed Firmware (No Encryption)
```bash
python firmware_image_builder.py --file app.bin --devID 1234
```
*Note: If the `--devID` parameter is not specified, it will assume the default value `0xFFFF`.*

### 4. Building an Encrypted and Signed Firmware
```bash
python firmware_image_builder.py --file app.bin --cipher AES256 --key [64_HEX_CHARS] --privKeyPwd ask
```
*Note: The first firmware is encrypted with a default key consisting of a string of 32 0xFF numbers, and we provide the --newKey argument with a new AES256 key.*


## 🏗 Binary Image Structure

The builder produces a 128-byte header followed by the firmware data.

| Offset | Size (Bytes) | Field | Description |
| :--- | :--- | :--- | :--- |
| 0x00 | 1 | Version | Format version (default 0x11) |
| 0x01 | 1 | Mode | Bitmask for signature/hash/cipher types |
| 0x02 | 2 | Device ID | Target device identifier (Little Endian) |
| 0x04 | 4 | Timestamp | Packed YYYY/MM/DD/HH/MM bitfield |
| 0x08 | 4 | FW Size | Total size of the firmware data |
| 0x0C | 4 | FW CRC32 | Hardware-compatible checksum |
| 0x10 | 64 | Signature | ECDSA P-256 Signature (R + S) |
| 0x50 | 16 | Cipher IV | AES Initialization Vector |
| 0x60 | 32 | New Key | Encrypted key for distribution |
| 0x80 | N | Firmware | The actual application binary |



## ⚙️ Technical Implementation Details

### Mode Bitfield Configuration
The `mode` byte is constructed as:
* **Bits 7-6**: Signature (00 = ECDSA P-256)
* **Bits 5-4**: Hash (00 = SHA256)
* **Bits 3-2**: New Key Cipher (00 =  No `New Key` attached, 01 = AES256)
* **Bits 1-0**: Firmware Cipher (00 = None, 01 = AES256)

### Firmware Padding and Activation
If the last 4 bytes of the input are `0xFFFFFFFF`, the script appends `0xFEEDBEEF` to ensure correct processing by the bootloader.

### CRC32 Algorithm
The `GD32CRC` class uses polynomial `0x04C11DB7`. It processes data in 32-bit words, ensuring parity with GD32 hardware CRC units.



## ⚠️ Troubleshooting
* **Linux**: If the script fails during environment creation, you may need to install the venv module manually:
    ```bash
    sudo apt install python3-venv
    ```
* **Windows**: If the script says "python is not found", ensure Python is selected in your Environment Variables.
* **Missing Requirements**: If `requirements.txt` is missing, the scripts will provide a warning but will still successfully set up the virtual environment.
* **Firmware Size**: The script expects firmware size to be a multiple of 4 bytes (uint32_t).



## 📄 License
Copyright © 2025-2026 Michal Protasowicki

This tool is released under the **MIT License**.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](../LICENSE)

## Support
If You find my projects interesting and You wanted to support my work, You can give me a cup of coffee or a keg of beer :)

[![PayPal Direct](https://badgen.net/badge/icon/Support%20me%20by%20PayPal?icon=kofi&label&scale=1.5&color=blue)](https://www.paypal.me/michpro)&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[![ko-fi](https://badgen.net/badge/icon/Support%20me%20on%20Ko-fi?icon=kofi&label&scale=1.5&color=red)](https://ko-fi.com/F1F24CEW1)&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[![Coinbase](https://badgen.net/badge/icon/Support%20me%20with%20cryptocurrencies?icon=kofi&label&scale=1.5&color=blue)](https://commerce.coinbase.com/checkout/ec299320-cbed-475d-976e-fdf37c1ac3d0)
