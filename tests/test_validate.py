"""Tests for the --validate command (validate_file function)."""

import struct
import tempfile
import os
import unittest

from src.common import ValidationResult, validate_file, FTXT_MAGIC, FTXT_HEADER_SIZE
from src.crypto import encode_ecd, ECD_MAGIC, HEADER_SIZE as CRYPTO_HEADER_SIZE
from src.jkr_compress import compress_jkr_hfi, compress_jkr_raw
from src.jkr_decompress import JKR_MAGIC, CompressionType


class TestValidateFile(unittest.TestCase):
    """Test validate_file with various file types."""

    def _write_temp(self, data: bytes) -> str:
        """Write data to a temp file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.write(fd, data)
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_nonexistent_file(self):
        result = validate_file("/nonexistent/file.bin")
        self.assertFalse(result.valid)
        self.assertIn("not found", result.error)

    def test_empty_file(self):
        path = self._write_temp(b"")
        result = validate_file(path)
        self.assertFalse(result.valid)
        self.assertEqual(result.file_size, 0)
        self.assertIn("empty", result.error)

    def test_plain_binary(self):
        data = b"\x00" * 256
        path = self._write_temp(data)
        result = validate_file(path)
        self.assertTrue(result.valid)
        self.assertEqual(result.file_size, 256)
        self.assertEqual(result.layers, [])
        self.assertEqual(result.inner_format, "Raw binary data")

    def test_ecd_encrypted(self):
        plaintext = b"\x00" * 64
        encrypted = encode_ecd(plaintext, key_index=4)
        path = self._write_temp(encrypted)
        result = validate_file(path)
        self.assertTrue(result.valid)
        self.assertEqual(len(result.layers), 1)
        self.assertIn("ECD encrypted", result.layers[0])
        self.assertIn("key index 4", result.layers[0])
        self.assertEqual(result.inner_format, "Raw binary data")

    def test_jkr_compressed(self):
        plaintext = b"\x00" * 128
        compressed = compress_jkr_raw(plaintext)
        path = self._write_temp(compressed)
        result = validate_file(path)
        self.assertTrue(result.valid)
        self.assertEqual(len(result.layers), 1)
        self.assertIn("JKR compressed", result.layers[0])
        self.assertIn("128", result.layers[0])  # decompressed size

    def test_jkr_hfi_compressed(self):
        plaintext = b"Hello world! " * 100
        compressed = compress_jkr_hfi(plaintext)
        path = self._write_temp(compressed)
        result = validate_file(path)
        self.assertTrue(result.valid)
        self.assertIn("JKR compressed", result.layers[0])
        self.assertIn("HFI", result.layers[0])

    def test_ecd_plus_jkr(self):
        plaintext = b"\x00" * 128
        compressed = compress_jkr_raw(plaintext)
        encrypted = encode_ecd(compressed, key_index=4)
        path = self._write_temp(encrypted)
        result = validate_file(path)
        self.assertTrue(result.valid)
        self.assertEqual(len(result.layers), 2)
        self.assertIn("ECD encrypted", result.layers[0])
        self.assertIn("JKR compressed", result.layers[1])

    def test_ftxt_file(self):
        # Build a minimal FTXT: magic + padding + count + text_block_size + strings
        strings = [b"Hello\x00", b"World\x00"]
        text_block = b"".join(strings)
        header = struct.pack("<I6xHI", FTXT_MAGIC, len(strings), len(text_block))
        data = header + text_block
        path = self._write_temp(data)
        result = validate_file(path)
        self.assertTrue(result.valid)
        self.assertIn("FTXT", result.inner_format)
        self.assertIn("2 strings", result.inner_format)

    def test_truncated_ecd(self):
        # Valid ECD header but payload truncated
        header = struct.pack("<IHHI", ECD_MAGIC, 4, 0, 9999)
        # Only provide the header, no payload
        path = self._write_temp(header)
        result = validate_file(path)
        self.assertFalse(result.valid)
        self.assertIn("ECD", result.layers[0])
        self.assertIn("failed", result.error.lower())

    def test_corrupt_jkr(self):
        # Valid JKR magic but data_offset points past end of file
        header = struct.pack("<IHHII", JKR_MAGIC, 0x108, CompressionType.HFI, 9999, 100)
        data = header + b"\xff" * 4
        path = self._write_temp(data)
        result = validate_file(path)
        self.assertFalse(result.valid)
        self.assertIn("JKR compressed", result.layers[0])
        self.assertIn("failed", result.error.lower())

    def test_result_dataclass(self):
        result = ValidationResult(
            file_path="test.bin", file_size=100,
            layers=["ECD encrypted (key index 4)"],
            inner_format="Raw binary data",
            valid=True, error=None,
        )
        self.assertEqual(result.file_path, "test.bin")
        self.assertEqual(result.file_size, 100)
        self.assertTrue(result.valid)


if __name__ == "__main__":
    unittest.main()
