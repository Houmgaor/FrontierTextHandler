# -*- coding: utf-8 -*-
"""
ECD/EXF encryption and decryption for Monster Hunter Frontier files.

Ported from ReFrontier (C#) by Houmgaor.
Adapted for FrontierTextHandler.

Supports two encryption formats:
- ECD (0x1A646365): LCG-based encryption with nibble Feistel cipher
- EXF (0x1A667865): LCG-based 16-byte XOR key with position-dependent transform

With major help from enler (original reverse engineering).
"""

import struct
import zlib
from typing import Tuple


class CryptoError(ValueError):
    """Raised when encryption or decryption fails."""
    pass


# Magic bytes for encrypted file formats
ECD_MAGIC = 0x1A646365  # "ecd\x1A" in little-endian
EXF_MAGIC = 0x1A667865  # "exf\x1A" in little-endian

# Header size for both formats
HEADER_SIZE = 16

# Default key index used by all known MHF files (100% of 1,962 analyzed files)
DEFAULT_KEY_INDEX = 4


# ECD/EXF encryption keys containing LCG (Linear Congruential Generator) parameters.
# Structure: 6 key sets for ECD, 5 for EXF; 8 bytes each (multiplier + increment).
# Source: Reverse-engineered from game executable.
#
# Key Index Analysis:
#   0: 0x4A4B522E / 1 (unique)
#   1: 0x00010DCD / 1 (same as 2, 3)
#   2: 0x00010DCD / 1 (same as 1, 3)
#   3: 0x00010DCD / 1 (same as 1, 2)
#   4: 0x0019660D / 3 (ALL MHF files use this - famous "Numerical Recipes" constant)
#   5: 0x7D2B89DD / 1 (unique)
_RND_BUF_ECD = bytes([
    0x4A, 0x4B, 0x52, 0x2E, 0x00, 0x00, 0x00, 0x01,  # Key 0
    0x00, 0x01, 0x0D, 0xCD, 0x00, 0x00, 0x00, 0x01,  # Key 1
    0x00, 0x01, 0x0D, 0xCD, 0x00, 0x00, 0x00, 0x01,  # Key 2
    0x00, 0x01, 0x0D, 0xCD, 0x00, 0x00, 0x00, 0x01,  # Key 3
    0x00, 0x19, 0x66, 0x0D, 0x00, 0x00, 0x00, 0x03,  # Key 4 (default)
    0x7D, 0x2B, 0x89, 0xDD, 0x00, 0x00, 0x00, 0x01,  # Key 5
])

_RND_BUF_EXF = bytes([
    0x4A, 0x4B, 0x52, 0x2E, 0x00, 0x00, 0x00, 0x01,  # Key 0
    0x00, 0x01, 0x0D, 0xCD, 0x00, 0x00, 0x00, 0x01,  # Key 1
    0x00, 0x01, 0x0D, 0xCD, 0x00, 0x00, 0x00, 0x01,  # Key 2
    0x00, 0x01, 0x0D, 0xCD, 0x00, 0x00, 0x00, 0x01,  # Key 3
    0x02, 0xE9, 0x0E, 0xDD, 0x00, 0x00, 0x00, 0x03,  # Key 4
])


def _load_uint32_be(buffer: bytes, offset: int) -> int:
    """Load 4 consecutive bytes as a big-endian unsigned integer."""
    return (buffer[offset] << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3]


def _get_rnd_ecd(ecd_key: int, rnd: int) -> Tuple[int, int]:
    """
    Generate next LCG value for ECD encryption.

    :param ecd_key: Key index (0-5)
    :param rnd: Current LCG state
    :return: Tuple of (new_rnd, xorpad_value)
    """
    multiplier = _load_uint32_be(_RND_BUF_ECD, 8 * ecd_key)
    increment = _load_uint32_be(_RND_BUF_ECD, 8 * ecd_key + 4)
    rnd = (rnd * multiplier + increment) & 0xFFFFFFFF
    return rnd, rnd


# ============================================================================
# Detection functions
# ============================================================================


def is_ecd_file(data: bytes) -> bool:
    """
    Check if data starts with ECD magic bytes.

    :param data: Raw file data.
    :return: True if this is an ECD encrypted file.
    """
    if len(data) < 4:
        return False
    magic = struct.unpack("<I", data[:4])[0]
    return magic == ECD_MAGIC


def is_exf_file(data: bytes) -> bool:
    """
    Check if data starts with EXF magic bytes.

    :param data: Raw file data.
    :return: True if this is an EXF encrypted file.
    """
    if len(data) < 4:
        return False
    magic = struct.unpack("<I", data[:4])[0]
    return magic == EXF_MAGIC


def is_encrypted_file(data: bytes) -> bool:
    """
    Check if data is an ECD or EXF encrypted file.

    :param data: Raw file data.
    :return: True if this is an encrypted file.
    """
    return is_ecd_file(data) or is_exf_file(data)


# ============================================================================
# ECD Encryption (primary format)
# ============================================================================


def decode_ecd(data: bytes) -> bytes:
    """
    Decrypt an ECD encrypted file.

    ECD Header Structure (16 bytes):
    - Bytes 0-3: Magic number (0x1A646365 "ecd\\x1A")
    - Bytes 4-5: Key index for LCG parameter selection
    - Bytes 6-7: (unused/padding)
    - Bytes 8-11: Payload size (encrypted data length)
    - Bytes 12-15: CRC32 of decrypted payload

    :param data: Complete ECD file data (header + encrypted payload).
    :return: Decrypted payload (without header).
    :raises CryptoError: If the data is invalid or too short.
    """
    if len(data) < HEADER_SIZE:
        raise CryptoError(f"ECD buffer too small: {len(data)} bytes (minimum {HEADER_SIZE} required)")

    if not is_ecd_file(data):
        raise CryptoError(f"Invalid ECD magic: expected 0x{ECD_MAGIC:08x}, got 0x{struct.unpack('<I', data[:4])[0]:08x}")

    ecd_key = struct.unpack("<H", data[4:6])[0]
    payload_size = struct.unpack("<I", data[8:12])[0]
    crc32 = struct.unpack("<I", data[12:16])[0]

    if ecd_key > 5:
        raise CryptoError(f"Invalid ECD key index: {ecd_key} (must be 0-5)")

    if len(data) < HEADER_SIZE + payload_size:
        raise CryptoError(
            f"ECD data truncated: expected {HEADER_SIZE + payload_size} bytes, "
            f"got {len(data)}"
        )

    # Initialize LCG state: rotate CRC32 and set LSB to ensure odd value
    rnd = ((crc32 << 16) | (crc32 >> 16) | 1) & 0xFFFFFFFF
    rnd, xorpad = _get_rnd_ecd(ecd_key, rnd)

    r8 = xorpad & 0xFF  # Previous decrypted byte for feedback chain

    output = bytearray(payload_size)

    for i in range(payload_size):
        rnd, xorpad = _get_rnd_ecd(ecd_key, rnd)

        encrypted_byte = data[HEADER_SIZE + i]
        r11 = encrypted_byte ^ r8  # XOR with previous output (cipher feedback)
        r12 = (r11 >> 4) & 0xFF  # Extract high nibble

        # 8-round Feistel-like nibble transformation
        for _ in range(8):
            r10 = xorpad ^ r11
            r11 = r12
            r12 = (r12 ^ r10) & 0xFF
            xorpad >>= 4

        # Recombine nibbles: low nibble from r12, high nibble from r11
        r8 = (r12 & 0xF) | ((r11 & 0xF) << 4)
        output[i] = r8

    return bytes(output)


def encode_ecd(data: bytes, key_index: int = DEFAULT_KEY_INDEX) -> bytes:
    """
    Encrypt data as ECD format.

    Creates a complete ECD file with 16-byte header and encrypted payload.

    :param data: Plaintext data to encrypt.
    :param key_index: Key index to use (0-5). Defaults to 4 (used by all MHF files).
    :return: Complete ECD file (header + encrypted payload).
    :raises CryptoError: If key_index is invalid.
    """
    if key_index < 0 or key_index > 5:
        raise CryptoError(f"Invalid key index: {key_index} (must be 0-5)")

    payload_size = len(data)
    crc32 = zlib.crc32(data) & 0xFFFFFFFF

    # Build header
    header = bytearray(HEADER_SIZE)
    struct.pack_into("<I", header, 0, ECD_MAGIC)
    struct.pack_into("<H", header, 4, key_index)
    # Bytes 6-7 are padding (zero)
    struct.pack_into("<I", header, 8, payload_size)
    struct.pack_into("<I", header, 12, crc32)

    # Initialize LCG state
    rnd = ((crc32 << 16) | (crc32 >> 16) | 1) & 0xFFFFFFFF
    rnd, xorpad = _get_rnd_ecd(key_index, rnd)

    r8 = xorpad & 0xFF

    output = bytearray(HEADER_SIZE + payload_size)
    output[:HEADER_SIZE] = header

    for i in range(payload_size):
        rnd, xorpad = _get_rnd_ecd(key_index, rnd)

        plaintext_byte = data[i]
        r11 = 0
        r12 = 0

        # Same 8-round transformation but for encryption
        for _ in range(8):
            r10 = xorpad ^ r11
            r11 = r12
            r12 = (r12 ^ r10) & 0xFF
            xorpad >>= 4

        dig2 = plaintext_byte
        dig1 = (dig2 >> 4) & 0xFF
        dig1 ^= r11
        dig2 ^= r12
        dig1 ^= dig2

        rr = (dig2 & 0xF) | ((dig1 & 0xF) << 4)
        rr = rr ^ r8
        output[HEADER_SIZE + i] = rr
        r8 = plaintext_byte

    return bytes(output)


def encode_ecd_with_meta(data: bytes, meta: bytes) -> bytes:
    """
    Encrypt data as ECD format using an existing header/meta.

    This allows re-encrypting a file using the original key index
    preserved in the .meta file.

    :param data: Plaintext data to encrypt.
    :param meta: Original ECD header (at least 6 bytes with magic and key index).
    :return: Complete ECD file (header + encrypted payload).
    :raises CryptoError: If meta is invalid or too short.
    """
    if len(meta) < 6:
        raise CryptoError(f"ECD meta too small: {len(meta)} bytes (minimum 6 required)")

    if not is_ecd_file(meta):
        raise CryptoError("Invalid ECD magic in meta")

    key_index = struct.unpack("<H", meta[4:6])[0]
    return encode_ecd(data, key_index=key_index)


# ============================================================================
# EXF Encryption (alternative format)
# ============================================================================


def _create_xorkey_exf(header: bytes) -> bytes:
    """
    Generate 16-byte XOR key for EXF decryption using LCG.

    :param header: First 16 bytes of the EXF file.
    :return: 16-byte XOR key buffer.
    """
    key_buffer = bytearray(16)
    index = struct.unpack("<H", header[4:6])[0]
    temp_val = struct.unpack("<I", header[12:16])[0]
    value = temp_val

    for i in range(4):
        multiplier = _load_uint32_be(_RND_BUF_EXF, index * 8)
        increment = _load_uint32_be(_RND_BUF_EXF, index * 8 + 4)
        temp_val = (temp_val * multiplier + increment) & 0xFFFFFFFF
        key = temp_val ^ value
        struct.pack_into("<I", key_buffer, i * 4, key)

    return bytes(key_buffer)


def decode_exf(data: bytes) -> bytes:
    """
    Decrypt an EXF encrypted file.

    EXF Header Structure (16 bytes):
    - Bytes 0-3: Magic number (0x1A667865 "exf\\x1A")
    - Bytes 4-5: Key index for LCG parameter selection
    - Bytes 12-15: Seed value for XOR key generation

    :param data: Complete EXF file data (header + encrypted payload).
    :return: Decrypted payload (without header).
    :raises CryptoError: If the data is invalid or too short.
    """
    if len(data) < HEADER_SIZE:
        raise CryptoError(f"EXF buffer too small: {len(data)} bytes (minimum {HEADER_SIZE} required)")

    if not is_exf_file(data):
        raise CryptoError(f"Invalid EXF magic: expected 0x{EXF_MAGIC:08x}, got 0x{struct.unpack('<I', data[:4])[0]:08x}")

    header = data[:HEADER_SIZE]
    keybuf = _create_xorkey_exf(header)

    output = bytearray(len(data) - HEADER_SIZE)

    for i in range(HEADER_SIZE, len(data)):
        r28 = i - HEADER_SIZE  # Position offset from payload start
        r8 = data[i]  # Read encrypted byte
        index = r28 & 0xF  # Low nibble of position -> key index
        r4 = r8 ^ r28  # XOR with position
        r12 = keybuf[index]  # Lookup key byte by position nibble
        r0 = (r4 & 0xF0) >> 4  # High nibble of XOR result
        r7 = keybuf[r0]  # Lookup key byte by high nibble
        r9 = r4 >> 4  # Shift r4 right by nibble
        r5 = r7 >> 4  # Shift key byte right by nibble
        r9 ^= r12  # XOR with first key lookup
        r26 = r5 ^ r4  # XOR shifted key with r4
        # Recombine: low nibble from r26, high nibble from r9
        r26 = (r26 & ~0xF0) | ((r9 & 0xF) << 4)
        output[r28] = r26 & 0xFF

    return bytes(output)


def encode_exf(data: bytes, meta: bytes) -> bytes:
    """
    Encrypt data as EXF format.

    EXF encryption requires the original header because the XOR key
    is derived from header values. There is no way to create a valid
    EXF file without the original header.

    :param data: Plaintext data to encrypt.
    :param meta: Original EXF header (16 bytes with key index and seed).
    :return: Complete EXF file (header + encrypted payload).
    :raises CryptoError: If meta is invalid or too short.
    """
    if len(meta) < HEADER_SIZE:
        raise CryptoError(f"EXF meta too small: {len(meta)} bytes (minimum {HEADER_SIZE} required)")

    if not is_exf_file(meta):
        raise CryptoError("Invalid EXF magic in meta")

    keybuf = _create_xorkey_exf(meta)

    output = bytearray(HEADER_SIZE + len(data))
    output[:HEADER_SIZE] = meta[:HEADER_SIZE]

    # Encrypt each byte using brute-force search
    for i in range(len(data)):
        position = i
        plaintext = data[i]
        encrypted = _find_encrypted_byte_exf(plaintext, position, keybuf)
        output[HEADER_SIZE + i] = encrypted

    return bytes(output)


def _find_encrypted_byte_exf(plaintext: int, position: int, keybuf: bytes) -> int:
    """
    Find the encrypted byte value that produces the desired plaintext when decrypted.

    This is a brute-force search over all 256 possible byte values.

    :param plaintext: The desired decrypted byte value.
    :param position: Position offset from payload start.
    :param keybuf: 16-byte XOR key buffer.
    :return: The encrypted byte value.
    :raises CryptoError: If no valid encrypted byte is found (should never happen).
    """
    for candidate in range(256):
        r8 = candidate
        index = position & 0xF
        r4 = r8 ^ position
        r12 = keybuf[index]
        r0 = (r4 & 0xF0) >> 4
        r7 = keybuf[r0]
        r9 = r4 >> 4
        r5 = r7 >> 4
        r9 ^= r12
        r26 = r5 ^ r4
        r26 = (r26 & ~0xF0) | ((r9 & 0xF) << 4)

        if (r26 & 0xFF) == plaintext:
            return candidate

    raise CryptoError(f"Failed to find encrypted byte for plaintext 0x{plaintext:02X} at position {position}")


# ============================================================================
# Unified interface
# ============================================================================


def decrypt(data: bytes) -> Tuple[bytes, bytes]:
    """
    Decrypt an ECD or EXF encrypted file.

    This is the unified interface that auto-detects the encryption format.

    :param data: Complete encrypted file data.
    :return: Tuple of (decrypted_payload, header_for_reencryption).
             The header can be passed to encrypt() for re-encryption.
    :raises CryptoError: If the data is not encrypted or decryption fails.
    """
    if is_ecd_file(data):
        return decode_ecd(data), data[:HEADER_SIZE]
    elif is_exf_file(data):
        return decode_exf(data), data[:HEADER_SIZE]
    else:
        raise CryptoError("Data is not an ECD or EXF encrypted file")


def encrypt(data: bytes, key_index: int = DEFAULT_KEY_INDEX, meta: bytes = None) -> bytes:
    """
    Encrypt data as ECD format (or EXF if meta is an EXF header).

    :param data: Plaintext data to encrypt.
    :param key_index: Key index for ECD encryption (0-5). Ignored if meta is provided.
    :param meta: Optional header from original file. If provided and is EXF,
                 will use EXF encryption. Otherwise uses ECD.
    :return: Complete encrypted file (header + payload).
    :raises CryptoError: If encryption fails.
    """
    if meta is not None:
        if is_exf_file(meta):
            return encode_exf(data, meta)
        elif is_ecd_file(meta):
            return encode_ecd_with_meta(data, meta)
        else:
            # Meta provided but not recognized - use it to extract key index if possible
            if len(meta) >= 6:
                key_index = struct.unpack("<H", meta[4:6])[0]
                if key_index > 5:
                    key_index = DEFAULT_KEY_INDEX

    return encode_ecd(data, key_index=key_index)
