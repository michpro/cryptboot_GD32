"""
Firmware Image Builder.

This script provides a set of tools to generate, encrypt, and sign firmware images
compatible with the CryptBootGD32 bootloader. It supports AES-256 encryption, 
ECDSA P-256 signatures, and GD32-compatible hardware CRC32 calculation.

@file firmware_image_builder.py
@copyright SPDX-FileCopyrightText: Copyright 2025-2026 by Michal Protasowicki
@license SPDX-License-Identifier: MIT
"""

# pylint: disable=line-too-long

import argparse
import os
import string
import struct
import getpass
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from pathlib import Path, PurePosixPath

try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError as e:
    raise SystemExit("Can't load module cryptography! Please install it: pip install cryptography") from e


AES256_IV_SIZE = 16
AES256_KEY_SIZE = 32
P256_SIGNATURE_LENGTH = 64

IV_FIELD_SIZE = AES256_IV_SIZE
KEY_SIZE = AES256_KEY_SIZE


# --------------------------------------------------------------------------------------------------------

@dataclass
class FirmwareCtx: # pylint: disable=too-many-instance-attributes
    """
    Firmware Context representing the 128-byte header and firmware data.
    This class handles the internal representation of the CryptBoot image format.
    """

    @staticmethod
    def generate_timestamp() -> list[int]:
        """
        Generates a 4-byte timestamp list (little-endian) based on the current time.
        Bit mapping: YYYY(12) MM(4) DD(5) HH(5) MM(6)
        
        :return: List of 4 bytes representing the packed timestamp.
        """
        now = datetime.now()
        # Packed bitfield construction
        timestamp_val = (
            ((now.year   & 0xFFF) << 20) |
            ((now.month  & 0x0F)  << 16) |
            ((now.day    & 0x1F)  << 11) |
            ((now.hour   & 0x1F)  << 6)  |
            (now.minute  & 0x3F)
        )
        # Convert to 4 bytes little-endian, then to list of uint8_t
        return list(timestamp_val.to_bytes(4, byteorder='little'))


    # firmwareCfg_t
    # version
    #   0x11 => 1.1
    #
    # mode
    #   ---------------------------------------------------------
    #   Bit Number   Contents
    #   ----------   --------------------------------------------
    #   7 ... 6      signature type
    #                    00 - ECDSA P-256
    #                    01 - RFU (Reserved for Future Use)
    #                    10 - RFU
    #                    11 - RFU
    #   5 ... 4      hash type
    #                    00 - SHA256
    #                    01 - RFU
    #                    10 - RFU
    #                    11 - RFU
    #   3 ... 2      new key cipher type
    #                    00 - no new key
    #                    01 - AES256
    #                    10 - RFU
    #                    11 - RFU
    #   1 ... 0      firmware cipher type
    #                    00 - none
    #                    01 - AES256
    #                    10 - RFU
    #                    11 - RFU
    #   ---------------------------------------------------------
    #
    # timeStamp
    #   ---------------------------------------------------------
    #   Bit Number   Contents
    #   ----------  --------------------------------------------
    #   31 ... 20    YYYY
    #   19 ... 16    MM (month)
    #   15 ... 11    DD
    #   10 ... 06    HH
    #   05 ... 00    MM (minute)
    #   ---------------------------------------------------------
    version:        int     = 0x11                                                              # uint8_t
    mode:           int     = 0x00                                                              # uint8_t
    device_id:      int     = 0xFFFF                                                            # uint16_t
    time_stamp:     list    = field(default_factory = generate_timestamp)                       # uint32_t
    firmware_size:  int     = 0                                                                 # uint32_t
    firmware_crc32: int     = 0                                                                 # uint32_t
    signature:      list    = field(default_factory = lambda: [0xFF] * P256_SIGNATURE_LENGTH)   # uint8_t [64]
    cipher_iv:      list    = field(default_factory = lambda: [0xFF] * IV_FIELD_SIZE)           # uint8_t [16]
    new_key:        list    = field(default_factory = lambda: [0xFF] * KEY_SIZE)                # uint8_t [32]
                                                                                                # -------------
                                                                                                # 128 bytes
    firmware:       list    = field(default_factory = list)


    def set_encryption(self, cipher: str):
        """
        Sets the firmware encryption algorithm and updates the mode bitfield.
        
        :param cipher: Encryption algorithm name ('NONE' or 'AES256').
        :raises SystemExit: If an unsupported encryption mode is provided.
        """
        self.mode &= 0xFC
        match cipher:
            case 'NONE':
                pass
            case 'AES256':
                self.mode |= 0x01
            case _:
                raise SystemExit("ERROR: Unsupported encryption mode!")


    def set_iv(self, iv: list[int]):
        """
        Sets the Initialization Vector (IV) for the firmware encryption.
        
        :param iv: List of bytes representing the IV.
        :raises SystemExit: If the IV length is incorrect for AES256.
        """
        if not len(iv) == AES256_IV_SIZE:
            raise SystemExit(f"ERROR: Length IV should be {AES256_IV_SIZE} bytes for AES256, and there are: {str(len(iv))} bytes.")
        self.cipher_iv = iv.copy()
        if len(self.cipher_iv) != IV_FIELD_SIZE:
            self.cipher_iv += [0xFF] * (IV_FIELD_SIZE - len(self.cipher_iv))


    def set_new_key(self, key: list[int], cipher: str):
        """
        Configures a new cryptographic key to be distributed within the firmware image.
        
        :param key: List of bytes representing the new key.
        :param cipher: Cipher algorithm used for the new key ('AES256').
        :raises SystemExit: If an unsupported cipher is provided.
        """
        self.mode &= 0xF3
        self.new_key = key.copy()
        match cipher:
            case 'AES256':
                self.mode |= 0x04
            case _:
                raise SystemExit("ERROR: Unsupported encryption mode!")


    def set_hash_type(self, hash_type: str):
        """
        Sets the hash algorithm used for firmware integrity and updates the mode bitfield.
        
        :param hash_type: Hash algorithm name (only 'SHA256' supported).
        :raises SystemExit: If an unsupported hash type is provided.
        """
        self.mode &= 0xCF
        match hash_type:
            case 'SHA256':
                pass
            case _:
                raise SystemExit("ERROR: Unsupported hash type!")


    def set_signature(self, signature: list[int]):
        """
        Sets the ECDSA P-256 signature for the firmware image.
        
        :param signature: List of 64 bytes representing the signature (R + S).
        :raises SystemExit: If the signature size is not 64 bytes.
        """
        self.mode &= 0x3F
        if len(signature) == 64:
            self.signature = signature
        else:
            raise SystemExit(f"ERROR: Incorrect P256 signature size! 64 bytes expected, {len(signature)} bytes received.")


    def get_descr_data_1st_chunk(self):
        """
        Constructs the first part of the header descriptor (before the signature).
        Includes version, mode, device ID, timestamp, size, and CRC.
        
        :return: List of bytes for the first header chunk.
        """
        descr = []
        descr.append(self.version)
        descr.append(self.mode)
        descr += list(self.device_id.to_bytes(2, byteorder='little'))
        descr += self.time_stamp
        descr += list(self.firmware_size.to_bytes(4, byteorder='little'))
        descr += list(self.firmware_crc32.to_bytes(4, byteorder='little'))
        return descr


    def get_descr_data_2nd_chunk(self):
        """
        Constructs the second part of the header descriptor (after the signature).
        Includes the IV and the new key field.
        
        :return: List of bytes for the second header chunk.
        """
        descr = []
        descr += self.cipher_iv
        descr += self.new_key
        return descr


    def serialize(self):
        """
        Serializes the entire firmware context into a single byte stream.
        The format is: Header Chunk 1 + Signature + Header Chunk 2 + Firmware Data.
        
        :return: Complete list of bytes representing the signed/encrypted firmware image.
        :raises SystemExit: If the actual firmware size doesn't match the header metadata.
        """
        firmware_data = self.get_descr_data_1st_chunk()
        firmware_data += self.signature
        firmware_data += self.get_descr_data_2nd_chunk()

        if self.firmware_size != len(self.firmware):
            raise SystemExit(f"ERROR: Firmware size does not match! {self.firmware_size} != {len(self.firmware)}")
        firmware_data += self.firmware
        return firmware_data


class AES256CFBStreamingEncryptor:
    """
    Helper class for performing AES-256 encryption in CFB mode.
    Supports streaming of data chunks while maintaining internal state.
    """
    def __init__(self, key: list[int], iv: list[int]):
        """
        Initializes the encryptor with a key and IV.
        
        :param key: 32-byte key as a list of uint8_t
        :param iv: 16-byte IV as a list of uint8_t
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes!")
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes!")

        # Initialize cipher and stateful encryptor
        self._cipher = Cipher(algorithms.AES(bytes(key)), modes.CFB(bytes(iv)), backend=default_backend()) # type: ignore
        self._encryptor = self._cipher.encryptor()


    def encrypt_chunk(self, data_chunk: list[int]) -> list[int]:
        """
        Encrypts a fragment of data and updates the internal state.
        
        :param data_chunk: Fragment of data as a list of uint8_t
        :return: Encrypted fragment as a list of uint8_t
        """
        ciphertext_bytes = self._encryptor.update(bytes(data_chunk))
        return list(ciphertext_bytes)


    def finalize(self) -> list[int]:
        """
        Finalizes the encryption process. 
        In CFB mode, this returns any remaining buffered bytes (usually empty).
        
        :return: Final block of encrypted bytes.
        """
        remaining_bytes = self._encryptor.finalize()
        return list(remaining_bytes)


class ECCManager:
    """
    A class to manage ECDSA P-256 key generation, export, import, signing, and verification.
    """
    __header_filename: str = "bootloader_public_key.h"
    __private_key_filename: str = "bootloader_private_key.pem"
    __private_key = None

    def set_private_key_filename(self, fname: str):
        """ Sets the filename for the private key PEM file. """
        self.__private_key_filename = fname


    def get_private_key_filename(self) -> str:
        """ Returns the current private key filename. """
        return self.__private_key_filename


    def get_header_filename(self) -> str:
        """ Returns the target filename for the exported public key C header. """
        return self.__header_filename


    def get_interactive_password(self) -> str:
        """ Prompts the user to enter a password for the private key via CLI. """
        return getpass.getpass("Enter password for the private key: ")


    def extract_public_key_from_private(self, priv_key: ec.EllipticCurvePrivateKey): # type: ignore
        """
        Extracts the public key from a private key and saves it as a C-style header file.
        The public key is saved in uncompressed format (X and Y coordinates).
        
        :param priv_key: The elliptic curve private key object.
        """
        public_key = priv_key.public_key()
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962, # type: ignore
            format=serialization.PublicFormat.UncompressedPoint # type: ignore
        )

        if len(pub_bytes) == 65 and pub_bytes[0] == 0x04:
            pub_bytes = pub_bytes[1:]

        rows = [", ".join(f"0x{b:02X}" for b in pub_bytes[i:i+16])
                for i in range(0, len(pub_bytes), 16)]

        # Join the rows outside the f-string expression
        joined_rows = ",\n        ".join(rows)

        # pylint: disable=trailing-whitespace
        h_content = f"""#pragma once

static const uint8_t BOOTLOADER_PUBLIC_KEY[] =
    {{
        {joined_rows}
    }};
"""
        with open(self.__header_filename, "w", encoding="ascii") as f:
            f.write(h_content)


    def generate_keys(self, password: Optional[str] = None):
        """
        Generates a new ECDSA P-256 key pair and saves them to files.
        
        :param password: Optional password to encrypt the private key PEM file.
        """
        private_key = ec.generate_private_key(ec.SECP256R1()) # type: ignore

        if password:
            password = self.get_interactive_password() if 'ask' == password.lower() else password
            pw_bytes = password.encode()
            encryption_algorithm = serialization.BestAvailableEncryption(pw_bytes) # type: ignore
        else:
            encryption_algorithm = serialization.NoEncryption() # type: ignore

        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM, # type: ignore
            format=serialization.PrivateFormat.PKCS8, # type: ignore
            encryption_algorithm=encryption_algorithm
        )

        with open(self.__private_key_filename, "wb") as f:
            f.write(pem_private)

        self.extract_public_key_from_private(private_key)

        print(f"Keys generated: {self.__header_filename}, {self.__private_key_filename}")


    def validate_pem_private_key(self, file_path: str, password: Optional[str] = None) -> bool:
        """
        Validates if a PEM file is a valid ECDSA private key using the SECP256R1 curve.
        
        :param file_path: Path to the .pem file.
        :param password: The password for the encrypted key (if applicable).
        :return: True if valid and matches requirements.
        :raises SystemExit: On validation errors (wrong curve, wrong format, incorrect password).
        """
        if not os.path.exists(file_path):
            raise SystemExit(f"Error: File {file_path} does not exist.")

        try:
            with open(file_path, "rb") as f:
                key_data = f.read()

            if password:
                password = self.get_interactive_password() if 'ask' == password.lower() else password
            # Convert password to bytes if provided
            pw_bytes = password.encode() if password else None

            # Attempt to load the key
            private_key = serialization.load_pem_private_key(key_data, password=pw_bytes) # type: ignore

            # 1. Verify it's an Elliptic Curve key
            if not isinstance(private_key, ec.EllipticCurvePrivateKey): # type: ignore
                raise SystemExit("Error: The file does not contain an Elliptic Curve private key.")

            # 2. Verify the curve is SECP256R1 (P-256) as required by ECCManager
            if not isinstance(private_key.curve, ec.SECP256R1): # type: ignore
                raise SystemExit(f"Error: Invalid curve. Expected P-256, found: {private_key.curve.name}")

            self.__private_key = private_key
            return True

        except (ValueError, TypeError) as e:
            raise SystemExit(f"Key validation error: {e}") from e
        except Exception as e: # pylint: disable=broad-exception-caught
            raise SystemExit(f"An unexpected error occurred: {e}, while validating Private Key!") from e


    def load_private_key(self, path: Optional[str] = None, password: Optional[str] = None) -> ec.EllipticCurvePrivateKey: # type: ignore
        """
        Loads an ECDSA private key from a PEM file.
        
        :param path: Path to the PEM file (defaults to class attribute if None).
        :param password: Password for the encrypted PEM file.
        :return: EllipticCurvePrivateKey object.
        :raises SystemExit: If loading fails.
        """
        path = path if path is not None else self.__private_key_filename
        with open(path, "rb") as f:
            key_data = f.read()
        if password:
            password = self.get_interactive_password() if 'ask' == password.lower() else password
        pw_bytes = password.encode() if password else None
        try:
            return serialization.load_pem_private_key(key_data, password=pw_bytes) # type: ignore
        except Exception as e: # pylint: disable=broad-exception-caught
            raise SystemExit(f"An unexpected error occurred: {e}, while load Private Key!") from e


    def sign_data(self, data: list[int], password: Optional[str] = None) -> list[int]:
        """
        Signs the provided data using ECDSA P-256 with SHA256.
        
        :param data: List of bytes to be signed.
        :param password: Password for the private key (if needed).
        :return: 64-byte signature (32 bytes R + 32 bytes S).
        """
        data_bytes = bytes(data)
        private_key = self.load_private_key(None, password) if self.__private_key is None else self.__private_key
        der_signature = private_key.sign(data_bytes, ec.ECDSA(hashes.SHA256())) # type: ignore
        r, s = decode_dss_signature(der_signature) # type: ignore
        return list(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))


    def verify_signature(self, data: list[int], signature: list[int], password: Optional[str] = None) -> bool:
        """
        Verifies an ECDSA P-256 signature against the data.
        
        :param data: Original data bytes.
        :param signature: 64-byte signature to verify.
        :param password: Password for the private key (to load the corresponding public key).
        :return: True if signature is valid, False otherwise.
        """
        if len(signature) != 64:
            return False
        try:
            r = int.from_bytes(bytes(signature[:32]), 'big')
            s = int.from_bytes(bytes(signature[32:]), 'big')
            der_sig = encode_dss_signature(r, s) # type: ignore
            if self.__private_key is None:
                public_key = self.load_private_key(None, password).public_key()
            else:
                public_key = self.__private_key.public_key()
            public_key.verify(der_sig, bytes(data), ec.ECDSA(hashes.SHA256())) # type: ignore
            return True
        except (InvalidSignature, Exception): # type: ignore # pylint: disable=broad-exception-caught
            return False


class GD32CRC: # pylint: disable=too-few-public-methods
    """
    Class responsible for calculating CRC32 compatible with GD32 hardware acceleration.
    """
    def __init__(self):
        """ Initializes the CRC32 lookup table. """
        self.__crc_table = self.__generate_crc32_table()


    def __generate_crc32_table(self):
        """
        Generates a 256-entry lookup table for the 0x04C11DB7 polynomial.
        This table is used to accelerate the software CRC calculation.
        
        :return: A list of 256 integers representing the CRC lookup table.
        """
        poly = 0x04C11DB7
        table = [0] * 256

        for i in range(256):
            c = i << 24
            for _ in range(8):
                if c & 0x80000000:
                    c = ((c << 1) ^ poly) & 0xFFFFFFFF
                else:
                    c = (c << 1) & 0xFFFFFFFF
            table[i] = c

        return table


    def crc32(self, data: list[int]) -> int:
        """
        Calculates the CRC32 checksum mimicking GD32 hardware behavior.
        Processes the input data in 32-bit words using Little Endian 
        interpretation to match the ARM Cortex-M memory access pattern.
        
        :param data: The input data (list of integers).
        :return: The calculated 32-bit CRC checksum.
        """
        crc = 0xFFFFFFFF

        # Use memoryview to avoid slicing/copying large byte arrays
        mv = memoryview(bytearray(data))
        length = len(data)

        # 1. Process 4 bytes (32-bit word) at a time
        num_words = length // 4
        for i in range(num_words):
            v = struct.unpack_from('<I', mv, i * 4)[0]

            crc ^= v
            for _ in range(4):
                crc = ((crc << 8) & 0xFFFFFFFF) ^ self.__crc_table[(crc >> 24) & 0xFF]

        # 2. Handle remaining 1-3 bytes (Remainder Logic)
        remainder = length % 4
        if remainder > 0:
            v = 0
            offset = num_words * 4
            for i in range(remainder):
                v |= (mv[offset + i] << (24 - (i * 8)))

            crc ^= v
            for _ in range(4):
                crc = ((crc << 8) & 0xFFFFFFFF) ^ self.__crc_table[(crc >> 24) & 0xFF]

        return crc


# --------------------------------------------------------------------------------------------------------

def check_dev_id_value(value):
    """ Validator for CLI hex device ID input. Checks if string is hex and has correct length. """
    value = value.upper().removeprefix("0X")
    if not all(char in string.hexdigits for char in value):
        raise SystemExit("ERROR: Device ID value is not a hexadecimal string")
    if len(value) != 4:
        raise SystemExit(f"ERROR: Correct device ID length is 2 bytes, and there are: {str(len(value) / 2)} bytes.")
    return str(value)


def check_key_value(value):
    """ Validator for CLI hex key input. Checks if string is hex and has correct length. """
    if not all(char in string.hexdigits for char in value):
        raise SystemExit("ERROR: key value is not a hexadecimal string")
    if len(value) != (2 * KEY_SIZE):
        raise SystemExit(f"ERROR: Correct key length is {KEY_SIZE} bytes, and there are: {str(len(value) / 2)} bytes.")
    return str(value)


def check_cipher_type(value):
    """ Validator for CLI cipher type. """
    in_value = str(value.upper())
    allowed_valuese = ['NONE', 'AES256']
    if in_value not in allowed_valuese:
        raise SystemExit(f"ERROR: {in_value} is unsupported encryption mode!")
    return in_value


def check_file_type(value):
    """ Validator for CLI firmware file. Ensures it is a .bin file and exists. """
    in_file = Path(value)
    if in_file.is_file():
        if not str(in_file).endswith('.bin'):
            raise SystemExit(f"ERROR: Specified file: {value} is NOT a '*.bin' type file!")
    else:
        raise SystemExit(f"ERROR: Specified file does not exist: {value}")
    return str(value)


def parse_input_args(priv_key_fname: str):
    """ Configures argparse and parses CLI arguments. """
    parser = argparse.ArgumentParser()
    parser.add_argument("--P256gen", action="store_true", help = "generate elliptic curve P-256 key pair")
    parser.add_argument("--privKeyPath", type = str, nargs = '?', const = priv_key_fname, default = priv_key_fname, help = "path to elliptic curve P-256 private key PEM file")
    parser.add_argument("--privKeyPwd", type = str, nargs = '?', const = 'ask', default = None, help = "elliptic curve P-256 private key password")
    parser.add_argument("--pubKeyGet", action="store_true", help = "extract elliptic curve P-256 public key from private key")
    parser.add_argument("--cipher", type = check_cipher_type, nargs = '?', const = 'AES256', default = 'NONE', help = "firmware encryption algorithm: [NONE, AES256]")
    parser.add_argument("--key", type = check_key_value, help = f"current [AES256] encryption key [{2 * KEY_SIZE} hex characters -> {KEY_SIZE} bytes]]")
    parser.add_argument("--newKey", type = check_key_value, help = f"NEW [AES256] cryptographic key to be included in the firmware image [{2 * KEY_SIZE} hex characters -> {KEY_SIZE} bytes]")
    parser.add_argument("--file", type = check_file_type, help = "firmware file to be processed")
    parser.add_argument("--devID", type = check_dev_id_value, nargs = '?', const = 'FFFF', default = 'FFFF', help = "device ID [4 hex characters -> 2 bytes]]")
    return parser.parse_args()


def process_password(args: argparse.Namespace, manager: ECCManager):
    """ Handles password logic: returns plain string, prompts user if 'ask', or returns None. """
    password = args.privKeyPwd
    if password:
        password = manager.get_interactive_password() if 'ask' == password.lower() else password
    else:
        password = None

    return password


def read_binary_from_file(path: str):
    """
    Reads binary data from a file.
    
    :param path: Path to the file.
    :return: Tuple of (data as list of bytes, length).
    """
    if path is not None:
        try:
            with open(path, "rb") as in_file:
                result: list = list(in_file.read())
            return result, len(result)
        except Exception as e: # pylint: disable=broad-exception-caught
            raise SystemExit(f"ERROR: {repr(e)} while trying to read from file: {path}") from e
    else:
        raise SystemExit("ERROR: Path to the file with original firmware has not been specified!")


def write_firmware_to_file(path: str, firmware: list[int]):
    """
    Saves the generated firmware image to a file with '.signed.bin' suffix.
    
    :param path: Base path (original filename).
    :param firmware: List of bytes to save.
    """
    file_path = str(PurePosixPath(path).stem)
    try:
        out_file_path = file_path + '.signed.bin'
        with open(out_file_path, "wb") as out_file:
            out_file.write(bytearray(firmware))
        print(f"File: {out_file_path} has been saved successfully.")
    except Exception as e:
        raise SystemExit(f"ERROR: {repr(e)} while trying to write to file: {out_file_path}") from e # type: ignore


def build_firmware(fw_ctx: FirmwareCtx, args: argparse.Namespace, manager: ECCManager, priv_key_pasw: Optional[str] = None) -> FirmwareCtx:
    """
    Core logic to assemble the firmware image: encrypts data (if needed), 
    calculates CRC, and signs the complete header + firmware package.
    
    :param fw_ctx: The firmware context to fill.
    :param args: Parsed command line arguments.
    :param manager: ECC manager for signing.
    :param priv_key_pasw: Password for the private key.
    :return: Updated FirmwareCtx.
    """
    # 1. Pre-validation of arguments (Fail-Fast)
    encrypt_enabled = args.cipher != 'NONE'
    has_new_key = bool(args.newKey)

    if has_new_key and not encrypt_enabled:
        raise SystemExit("ERROR: A new encryption key has been provided, but the firmware encryption option has not been selected!")

    if encrypt_enabled and args.key is None:
        raise SystemExit("ERROR: The firmware encryption option has been selected, but no key has been provided!")

    # 2. Setup Context based on validated state
    if encrypt_enabled:
        fw_ctx.set_encryption(args.cipher)
        fw_ctx.set_iv(list(bytearray(os.urandom(AES256_IV_SIZE))))

    if has_new_key:
        fw_ctx.set_new_key(list(bytearray.fromhex(args.newKey)), 'AES256')

    # 3. Data Processing (Integrity & Encryption)
    fw_ctx.set_hash_type('SHA256')
    fw_ctx.firmware, fw_ctx.firmware_size = read_binary_from_file(args.file)
    if len(fw_ctx.firmware) % 4 != 0:
        raise SystemExit("ERROR: Firmware is corrupted! Size of the firmware should be a multiple of size of 'uint32_t' !")
    if all(x == 0xFF for x in fw_ctx.firmware[-4:]):
        fw_ctx.firmware += [0xFE, 0xED, 0xBE, 0xEF]
        fw_ctx.firmware_size += 4
        print("Potential firmware activation issue - padding added.")

    gd32crc = GD32CRC()
    fw_ctx.firmware_crc32 = gd32crc.crc32(fw_ctx.firmware)

    fw_ctx.device_id = int(args.devID, 16)

    if encrypt_enabled:
        cipher_key = list(bytearray.fromhex(args.key))
        encryptor = AES256CFBStreamingEncryptor(cipher_key, fw_ctx.cipher_iv)

        if has_new_key:
            fw_ctx.new_key = encryptor.encrypt_chunk(fw_ctx.new_key)

        fw_ctx.firmware = encryptor.encrypt_chunk(fw_ctx.firmware)

        if len(encryptor.finalize()) != 0:
            raise SystemExit("ERROR: Unexpected data appeared during finalisation of the firmware encryption!")

    # 4. Final Signing
    data_to_sign = fw_ctx.get_descr_data_1st_chunk() + fw_ctx.get_descr_data_2nd_chunk() + fw_ctx.firmware
    fw_ctx.set_signature(manager.sign_data(data_to_sign, priv_key_pasw))

    return fw_ctx


def main():
    """ Main entry point of the script. """
    manager = ECCManager()
    args = parse_input_args(manager.get_private_key_filename())
    if args.P256gen is True:
        password = process_password(args, manager)
        manager.generate_keys(password)
    elif args.pubKeyGet is True:
        password = process_password(args, manager) if args.privKeyPwd else None
        if not manager.validate_pem_private_key(args.privKeyPath, password):
            raise SystemExit("An unexpected error occurred, while validating Private Key!")
        manager.extract_public_key_from_private(manager.load_private_key(args.privKeyPath, password))
        print(f"Key generated: {manager.get_header_filename()}")
    else:
        fw_ctx = FirmwareCtx()
        password = process_password(args, manager)
        if not manager.validate_pem_private_key(args.privKeyPath, password):
            raise SystemExit("An unexpected error occurred, while validating Private Key!")
        fw_ctx = build_firmware(fw_ctx, args, manager, password)
        write_firmware_to_file(args.file, fw_ctx.serialize())


if __name__ == "__main__":
    main()
