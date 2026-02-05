"""Unit tests for ECD/EXF encryption and decryption."""

import struct
import unittest

from src.crypto import (
    ECD_MAGIC,
    EXF_MAGIC,
    HEADER_SIZE,
    DEFAULT_KEY_INDEX,
    CryptoError,
    is_ecd_file,
    is_exf_file,
    is_encrypted_file,
    decode_ecd,
    encode_ecd,
    encode_ecd_with_meta,
    decode_exf,
    encode_exf,
    decrypt,
    encrypt,
)


class TestIsEcdFile(unittest.TestCase):
    """Test is_ecd_file detection."""

    def test_valid_ecd_magic(self):
        """Test detection with valid ECD magic bytes."""
        data = struct.pack("<I", ECD_MAGIC) + b"\x00" * 12
        self.assertTrue(is_ecd_file(data))

    def test_invalid_magic(self):
        """Test detection with invalid magic bytes."""
        data = b"NOTM" + b"\x00" * 12
        self.assertFalse(is_ecd_file(data))

    def test_too_short(self):
        """Test detection with data too short."""
        data = b"ecd"  # Only 3 bytes
        self.assertFalse(is_ecd_file(data))

    def test_empty_data(self):
        """Test detection with empty data."""
        self.assertFalse(is_ecd_file(b""))


class TestIsExfFile(unittest.TestCase):
    """Test is_exf_file detection."""

    def test_valid_exf_magic(self):
        """Test detection with valid EXF magic bytes."""
        data = struct.pack("<I", EXF_MAGIC) + b"\x00" * 12
        self.assertTrue(is_exf_file(data))

    def test_invalid_magic(self):
        """Test detection with invalid magic bytes."""
        data = b"NOTM" + b"\x00" * 12
        self.assertFalse(is_exf_file(data))


class TestIsEncryptedFile(unittest.TestCase):
    """Test is_encrypted_file detection."""

    def test_ecd_detected(self):
        """Test ECD file is detected as encrypted."""
        data = struct.pack("<I", ECD_MAGIC) + b"\x00" * 12
        self.assertTrue(is_encrypted_file(data))

    def test_exf_detected(self):
        """Test EXF file is detected as encrypted."""
        data = struct.pack("<I", EXF_MAGIC) + b"\x00" * 12
        self.assertTrue(is_encrypted_file(data))

    def test_other_not_detected(self):
        """Test non-encrypted file is not detected."""
        data = b"Not encrypted data" + b"\x00" * 12
        self.assertFalse(is_encrypted_file(data))


class TestDecodeEcd(unittest.TestCase):
    """Test decode_ecd function."""

    def test_decode_too_short(self):
        """Test decoding data too short raises error."""
        with self.assertRaises(CryptoError) as ctx:
            decode_ecd(b"\x00" * 10)
        self.assertIn("too small", str(ctx.exception))

    def test_decode_invalid_magic(self):
        """Test decoding invalid magic raises error."""
        data = b"NOPE" + b"\x00" * 12
        with self.assertRaises(CryptoError) as ctx:
            decode_ecd(data)
        self.assertIn("Invalid ECD magic", str(ctx.exception))

    def test_decode_invalid_key(self):
        """Test decoding with invalid key index raises error."""
        # Create header with key index 10 (invalid)
        header = struct.pack("<I", ECD_MAGIC)  # magic
        header += struct.pack("<H", 10)  # invalid key index
        header += b"\x00\x00"  # padding
        header += struct.pack("<I", 0)  # payload size
        header += struct.pack("<I", 0)  # crc32

        with self.assertRaises(CryptoError) as ctx:
            decode_ecd(header)
        self.assertIn("Invalid ECD key index", str(ctx.exception))


class TestEncodeEcd(unittest.TestCase):
    """Test encode_ecd function."""

    def test_encode_invalid_key(self):
        """Test encoding with invalid key index raises error."""
        with self.assertRaises(CryptoError) as ctx:
            encode_ecd(b"test", key_index=10)
        self.assertIn("Invalid key index", str(ctx.exception))

    def test_encode_negative_key(self):
        """Test encoding with negative key index raises error."""
        with self.assertRaises(CryptoError) as ctx:
            encode_ecd(b"test", key_index=-1)
        self.assertIn("Invalid key index", str(ctx.exception))


class TestEcdRoundTrip(unittest.TestCase):
    """Test ECD round-trip encryption/decryption."""

    def test_roundtrip_default_key(self):
        """Test round-trip with default key (index 4)."""
        original = b"Hello, World! This is a test."
        encrypted = encode_ecd(original)
        decrypted = decode_ecd(encrypted)
        self.assertEqual(decrypted, original)

    def test_roundtrip_all_keys(self):
        """Test round-trip with all 6 key indices."""
        original = b"Test data for key verification"

        for key_index in range(6):
            with self.subTest(key_index=key_index):
                encrypted = encode_ecd(original, key_index=key_index)
                decrypted = decode_ecd(encrypted)
                self.assertEqual(decrypted, original)

    def test_roundtrip_empty(self):
        """Test round-trip with empty data."""
        original = b""
        encrypted = encode_ecd(original)
        decrypted = decode_ecd(encrypted)
        self.assertEqual(decrypted, original)

    def test_roundtrip_single_byte(self):
        """Test round-trip with single byte."""
        original = b"X"
        encrypted = encode_ecd(original)
        decrypted = decode_ecd(encrypted)
        self.assertEqual(decrypted, original)

    def test_roundtrip_binary_data(self):
        """Test round-trip with all byte values."""
        original = bytes(range(256))
        encrypted = encode_ecd(original)
        decrypted = decode_ecd(encrypted)
        self.assertEqual(decrypted, original)

    def test_roundtrip_large_data(self):
        """Test round-trip with larger data (4KB+)."""
        original = bytes(range(256)) * 20  # 5KB
        encrypted = encode_ecd(original)
        decrypted = decode_ecd(encrypted)
        self.assertEqual(decrypted, original)

    def test_roundtrip_all_zeros(self):
        """Test round-trip with all zero bytes."""
        original = b"\x00" * 100
        encrypted = encode_ecd(original)
        decrypted = decode_ecd(encrypted)
        self.assertEqual(decrypted, original)

    def test_roundtrip_all_ones(self):
        """Test round-trip with all 0xFF bytes."""
        original = b"\xFF" * 100
        encrypted = encode_ecd(original)
        decrypted = decode_ecd(encrypted)
        self.assertEqual(decrypted, original)

    def test_roundtrip_alternating(self):
        """Test round-trip with alternating pattern."""
        original = b"\xAA\x55" * 50
        encrypted = encode_ecd(original)
        decrypted = decode_ecd(encrypted)
        self.assertEqual(decrypted, original)


class TestEcdWithMeta(unittest.TestCase):
    """Test encode_ecd_with_meta function."""

    def test_encode_with_meta_preserves_key(self):
        """Test that meta preserves the original key index."""
        original = b"Test data"

        # Encrypt with key 2
        encrypted_key2 = encode_ecd(original, key_index=2)
        meta = encrypted_key2[:HEADER_SIZE]

        # Re-encrypt with meta
        re_encrypted = encode_ecd_with_meta(original, meta)

        # Should use key 2 from meta
        key_from_result = struct.unpack("<H", re_encrypted[4:6])[0]
        self.assertEqual(key_from_result, 2)

        # Should round-trip correctly
        decrypted = decode_ecd(re_encrypted)
        self.assertEqual(decrypted, original)

    def test_encode_with_meta_too_short(self):
        """Test encoding with meta too short raises error."""
        with self.assertRaises(CryptoError) as ctx:
            encode_ecd_with_meta(b"test", b"\x00" * 4)
        self.assertIn("too small", str(ctx.exception))

    def test_encode_with_meta_invalid_magic(self):
        """Test encoding with invalid meta magic raises error."""
        meta = b"NOPE" + b"\x00" * 12
        with self.assertRaises(CryptoError) as ctx:
            encode_ecd_with_meta(b"test", meta)
        self.assertIn("Invalid ECD magic", str(ctx.exception))


class TestExfRoundTrip(unittest.TestCase):
    """Test EXF round-trip encryption/decryption."""

    def _make_exf_header(self, key_index: int = 4, seed: int = 0x12345678) -> bytes:
        """Create a valid EXF header for testing."""
        header = bytearray(HEADER_SIZE)
        struct.pack_into("<I", header, 0, EXF_MAGIC)
        struct.pack_into("<H", header, 4, key_index)
        # Bytes 6-11 are typically unused/padding
        struct.pack_into("<I", header, 12, seed)
        return bytes(header)

    def test_roundtrip_simple(self):
        """Test EXF round-trip with simple data."""
        original = b"Hello, World!"
        meta = self._make_exf_header()

        encrypted = encode_exf(original, meta)
        decrypted = decode_exf(encrypted)
        self.assertEqual(decrypted, original)

    def test_roundtrip_binary(self):
        """Test EXF round-trip with binary data."""
        original = bytes(range(256))
        meta = self._make_exf_header()

        encrypted = encode_exf(original, meta)
        decrypted = decode_exf(encrypted)
        self.assertEqual(decrypted, original)

    def test_roundtrip_different_seeds(self):
        """Test EXF round-trip with different seed values."""
        original = b"Test data for seed verification"

        for seed in [0x00000000, 0xFFFFFFFF, 0x12345678, 0xDEADBEEF]:
            with self.subTest(seed=hex(seed)):
                meta = self._make_exf_header(seed=seed)
                encrypted = encode_exf(original, meta)
                decrypted = decode_exf(encrypted)
                self.assertEqual(decrypted, original)

    def test_encode_exf_meta_too_short(self):
        """Test encoding EXF with meta too short raises error."""
        with self.assertRaises(CryptoError) as ctx:
            encode_exf(b"test", b"\x00" * 8)
        self.assertIn("too small", str(ctx.exception))

    def test_encode_exf_invalid_magic(self):
        """Test encoding EXF with invalid meta magic raises error."""
        meta = b"NOPE" + b"\x00" * 12
        with self.assertRaises(CryptoError) as ctx:
            encode_exf(b"test", meta)
        self.assertIn("Invalid EXF magic", str(ctx.exception))


class TestDecodeExf(unittest.TestCase):
    """Test decode_exf function."""

    def test_decode_too_short(self):
        """Test decoding data too short raises error."""
        with self.assertRaises(CryptoError) as ctx:
            decode_exf(b"\x00" * 10)
        self.assertIn("too small", str(ctx.exception))

    def test_decode_invalid_magic(self):
        """Test decoding invalid magic raises error."""
        data = b"NOPE" + b"\x00" * 12
        with self.assertRaises(CryptoError) as ctx:
            decode_exf(data)
        self.assertIn("Invalid EXF magic", str(ctx.exception))


class TestUnifiedDecrypt(unittest.TestCase):
    """Test the unified decrypt function."""

    def test_decrypt_ecd(self):
        """Test decrypt auto-detects ECD."""
        original = b"Test data for ECD"
        encrypted = encode_ecd(original)

        decrypted, header = decrypt(encrypted)
        self.assertEqual(decrypted, original)
        self.assertTrue(is_ecd_file(header))

    def test_decrypt_exf(self):
        """Test decrypt auto-detects EXF."""
        original = b"Test data for EXF"
        # Create EXF header
        meta = bytearray(HEADER_SIZE)
        struct.pack_into("<I", meta, 0, EXF_MAGIC)
        struct.pack_into("<H", meta, 4, 4)  # key index
        struct.pack_into("<I", meta, 12, 0x12345678)  # seed
        meta = bytes(meta)

        encrypted = encode_exf(original, meta)

        decrypted, header = decrypt(encrypted)
        self.assertEqual(decrypted, original)
        self.assertTrue(is_exf_file(header))

    def test_decrypt_non_encrypted_raises(self):
        """Test decrypt raises error for non-encrypted data."""
        data = b"Not encrypted at all"
        with self.assertRaises(CryptoError) as ctx:
            decrypt(data)
        self.assertIn("not an ECD or EXF", str(ctx.exception))


class TestUnifiedEncrypt(unittest.TestCase):
    """Test the unified encrypt function."""

    def test_encrypt_default(self):
        """Test encrypt with default parameters."""
        original = b"Test data"
        encrypted = encrypt(original)

        # Should be ECD with key 4
        self.assertTrue(is_ecd_file(encrypted))
        key_index = struct.unpack("<H", encrypted[4:6])[0]
        self.assertEqual(key_index, DEFAULT_KEY_INDEX)

        # Should round-trip
        decrypted = decode_ecd(encrypted)
        self.assertEqual(decrypted, original)

    def test_encrypt_with_key_index(self):
        """Test encrypt with specific key index."""
        original = b"Test data"
        encrypted = encrypt(original, key_index=2)

        key_index = struct.unpack("<H", encrypted[4:6])[0]
        self.assertEqual(key_index, 2)

    def test_encrypt_with_ecd_meta(self):
        """Test encrypt uses ECD when given ECD meta."""
        original = b"Test data"

        # Create ECD meta with key 3
        meta = encode_ecd(b"dummy", key_index=3)[:HEADER_SIZE]

        encrypted = encrypt(original, meta=meta)
        self.assertTrue(is_ecd_file(encrypted))
        key_index = struct.unpack("<H", encrypted[4:6])[0]
        self.assertEqual(key_index, 3)

    def test_encrypt_with_exf_meta(self):
        """Test encrypt uses EXF when given EXF meta."""
        original = b"Test data"

        # Create EXF meta
        meta = bytearray(HEADER_SIZE)
        struct.pack_into("<I", meta, 0, EXF_MAGIC)
        struct.pack_into("<H", meta, 4, 4)
        struct.pack_into("<I", meta, 12, 0xDEADBEEF)
        meta = bytes(meta)

        encrypted = encrypt(original, meta=meta)
        self.assertTrue(is_exf_file(encrypted))

        # Should round-trip
        decrypted = decode_exf(encrypted)
        self.assertEqual(decrypted, original)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases for encryption."""

    def test_encrypt_decrypt_1_byte_all_values(self):
        """Test all single byte values encrypt/decrypt correctly."""
        for byte_val in range(256):
            with self.subTest(byte_val=byte_val):
                original = bytes([byte_val])
                encrypted = encode_ecd(original)
                decrypted = decode_ecd(encrypted)
                self.assertEqual(decrypted, original)

    def test_encrypt_decrypt_varying_sizes(self):
        """Test various data sizes."""
        for size in [1, 2, 7, 15, 16, 17, 100, 255, 256, 1000, 4096]:
            with self.subTest(size=size):
                original = bytes([i % 256 for i in range(size)])
                encrypted = encode_ecd(original)
                decrypted = decode_ecd(encrypted)
                self.assertEqual(decrypted, original)

    def test_header_size(self):
        """Test that encrypted output has correct header size."""
        original = b"Test"
        encrypted = encode_ecd(original)

        # Header should be 16 bytes
        self.assertEqual(len(encrypted), HEADER_SIZE + len(original))

    def test_encrypted_output_differs_from_input(self):
        """Test that encrypted data is different from input."""
        original = b"Test data that should be encrypted"
        encrypted = encode_ecd(original)

        # Payload should be different (unless very unlikely coincidence)
        encrypted_payload = encrypted[HEADER_SIZE:]
        self.assertNotEqual(encrypted_payload, original)


class TestCryptoErrorMessages(unittest.TestCase):
    """Test that error messages are informative."""

    def test_ecd_too_small_message(self):
        """Test ECD too small error message contains size info."""
        try:
            decode_ecd(b"x" * 5)
        except CryptoError as e:
            self.assertIn("5 bytes", str(e))
            self.assertIn("16", str(e))

    def test_exf_too_small_message(self):
        """Test EXF too small error message contains size info."""
        try:
            decode_exf(b"x" * 5)
        except CryptoError as e:
            self.assertIn("5 bytes", str(e))
            self.assertIn("16", str(e))


class TestMagicConstants(unittest.TestCase):
    """Test magic constant values."""

    def test_ecd_magic_value(self):
        """Test ECD magic matches expected value."""
        # "ecd\x1A" in little-endian
        expected = int.from_bytes(b"ecd\x1A", "little")
        self.assertEqual(ECD_MAGIC, expected)

    def test_exf_magic_value(self):
        """Test EXF magic matches expected value."""
        # "exf\x1A" in little-endian
        expected = int.from_bytes(b"exf\x1A", "little")
        self.assertEqual(EXF_MAGIC, expected)

    def test_header_size_value(self):
        """Test header size is 16 bytes."""
        self.assertEqual(HEADER_SIZE, 16)

    def test_default_key_index(self):
        """Test default key index is 4."""
        self.assertEqual(DEFAULT_KEY_INDEX, 4)


if __name__ == "__main__":
    unittest.main()
