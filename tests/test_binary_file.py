"""Tests for src/binary_file.py — BinaryFile context manager."""

import os
import struct
import tempfile
import unittest

from src.binary_file import BinaryFile, InvalidPointerError


class TestBinaryFileFromBytes(unittest.TestCase):
    """Test BinaryFile.from_bytes() in-memory mode."""

    def test_create_from_bytes(self):
        data = b"\x01\x02\x03\x04"
        bfile = BinaryFile.from_bytes(data)
        self.assertIsNone(bfile.file_path)
        self.assertEqual(bfile.size, 4)

    def test_read(self):
        bfile = BinaryFile.from_bytes(b"\xAA\xBB\xCC\xDD")
        self.assertEqual(bfile.read(2), b"\xAA\xBB")
        self.assertEqual(bfile.read(2), b"\xCC\xDD")

    def test_read_int(self):
        data = struct.pack("<I", 42)
        bfile = BinaryFile.from_bytes(data)
        self.assertEqual(bfile.read_int(), 42)

    def test_read_int_max_u32(self):
        data = struct.pack("<I", 0xFFFFFFFF)
        bfile = BinaryFile.from_bytes(data)
        self.assertEqual(bfile.read_int(), 0xFFFFFFFF)

    def test_seek_and_tell(self):
        bfile = BinaryFile.from_bytes(b"\x00" * 10)
        self.assertEqual(bfile.tell(), 0)
        bfile.seek(5)
        self.assertEqual(bfile.tell(), 5)

    def test_seek_end(self):
        bfile = BinaryFile.from_bytes(b"\x00" * 10)
        bfile.seek(0, 2)  # SEEK_END
        self.assertEqual(bfile.tell(), 10)

    def test_write(self):
        bfile = BinaryFile.from_bytes(b"\x00" * 8)
        bfile.seek(0)
        bfile.write(b"\xFF\xFF")
        bfile.seek(0)
        self.assertEqual(bfile.read(2), b"\xFF\xFF")

    def test_write_int(self):
        bfile = BinaryFile.from_bytes(b"\x00" * 4)
        bfile.seek(0)
        bfile.write_int(12345)
        bfile.seek(0)
        self.assertEqual(bfile.read_int(), 12345)

    def test_size_property(self):
        bfile = BinaryFile.from_bytes(b"\x00" * 42)
        self.assertEqual(bfile.size, 42)

    def test_empty_data(self):
        bfile = BinaryFile.from_bytes(b"")
        self.assertEqual(bfile.size, 0)
        self.assertEqual(bfile.read(1), b"")


class TestBinaryFileContextManager(unittest.TestCase):
    """Test BinaryFile as a context manager with real files."""

    def _write_temp(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.write(fd, data)
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_open_read(self):
        data = struct.pack("<I", 999)
        path = self._write_temp(data)
        with BinaryFile(path, "rb") as bfile:
            self.assertEqual(bfile.read_int(), 999)
            self.assertEqual(bfile.size, 4)

    def test_open_read_write(self):
        data = struct.pack("<I", 0)
        path = self._write_temp(data)
        with BinaryFile(path, "r+b") as bfile:
            bfile.write_int(777)
            bfile.seek(0)
            self.assertEqual(bfile.read_int(), 777)

    def test_context_closes_file(self):
        path = self._write_temp(b"\x00" * 4)
        bfile = BinaryFile(path, "rb")
        with bfile:
            pass
        self.assertTrue(bfile.file.closed)

    def test_bytesio_not_closed_on_exit(self):
        """BytesIO-backed instances don't close on __exit__."""
        bfile = BinaryFile.from_bytes(b"\x00" * 4)
        bfile.__exit__(None, None, None)
        # BytesIO should still be usable
        bfile.seek(0)
        self.assertEqual(bfile.read(1), b"\x00")


class TestValidateOffset(unittest.TestCase):
    """Test BinaryFile.validate_offset."""

    def test_valid_offset_start(self):
        bfile = BinaryFile.from_bytes(b"\x00" * 10)
        bfile.validate_offset(0)  # Should not raise

    def test_valid_offset_end(self):
        bfile = BinaryFile.from_bytes(b"\x00" * 10)
        bfile.validate_offset(9)  # Should not raise

    def test_negative_offset(self):
        bfile = BinaryFile.from_bytes(b"\x00" * 10)
        with self.assertRaises(InvalidPointerError):
            bfile.validate_offset(-1)

    def test_offset_at_size(self):
        bfile = BinaryFile.from_bytes(b"\x00" * 10)
        with self.assertRaises(InvalidPointerError):
            bfile.validate_offset(10)

    def test_offset_way_past_end(self):
        bfile = BinaryFile.from_bytes(b"\x00" * 10)
        with self.assertRaises(InvalidPointerError):
            bfile.validate_offset(0xFFFF)

    def test_error_includes_context(self):
        bfile = BinaryFile.from_bytes(b"\x00" * 10)
        with self.assertRaises(InvalidPointerError) as ctx:
            bfile.validate_offset(100, context="test pointer")
        self.assertIn("test pointer", str(ctx.exception))

    def test_error_includes_hex_offset(self):
        bfile = BinaryFile.from_bytes(b"\x00" * 10)
        with self.assertRaises(InvalidPointerError) as ctx:
            bfile.validate_offset(0xFF)
        self.assertIn("0xff", str(ctx.exception))

    def test_error_includes_bounds(self):
        bfile = BinaryFile.from_bytes(b"\x00" * 10)
        with self.assertRaises(InvalidPointerError) as ctx:
            bfile.validate_offset(20)
        self.assertIn("0x9", str(ctx.exception))  # max valid = 9


class TestInvalidPointerError(unittest.TestCase):
    """Test InvalidPointerError is a ValueError."""

    def test_is_value_error(self):
        self.assertTrue(issubclass(InvalidPointerError, ValueError))

    def test_can_be_raised(self):
        with self.assertRaises(InvalidPointerError):
            raise InvalidPointerError("test")

    def test_caught_as_value_error(self):
        with self.assertRaises(ValueError):
            raise InvalidPointerError("test")


if __name__ == "__main__":
    unittest.main()
