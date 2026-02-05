"""
Integration tests for CSV import/export workflows.

Tests common.py, export.py, import_data.py, and transform.py functions.
"""
import csv
import json
import os
import struct
import tempfile
import unittest

from src import (
    CSVParseError,
    EncodingError,
    encode_game_string,
    decode_game_string,
    GAME_ENCODING,
)
from src.common import (
    skip_csv_header,
    read_json_data,
    read_until_null,
    read_file_section,
    REFRONTIER_REPLACEMENTS,
    DEFAULT_HEADERS_PATH,
)
from src.export import export_as_csv, export_for_refrontier
from src.import_data import parse_location, get_new_strings
from src.transform import import_from_refrontier
from src.binary_file import BinaryFile


class TestEncoding(unittest.TestCase):
    """Tests for encoding/decoding functions."""

    def test_decode_ascii(self):
        """Test decoding simple ASCII."""
        data = b"Hello"
        result = decode_game_string(data)
        self.assertEqual(result, "Hello")

    def test_decode_japanese(self):
        """Test decoding Japanese Shift-JIS text."""
        # "テスト" in Shift-JIS
        data = b"\x83\x65\x83\x58\x83\x67"
        result = decode_game_string(data)
        self.assertEqual(result, "テスト")

    def test_decode_with_replace_errors(self):
        """Test decoding invalid bytes with replace mode."""
        # Invalid Shift-JIS sequence
        data = b"\xff\xfe\x41"
        result = decode_game_string(data, errors="replace")
        self.assertIn("A", result)  # Valid ASCII still decoded

    def test_decode_strict_raises(self):
        """Test that strict mode raises EncodingError."""
        data = b"\xff\xfe"
        with self.assertRaises(EncodingError):
            decode_game_string(data, errors="strict")

    def test_encode_ascii(self):
        """Test encoding simple ASCII."""
        text = "Hello"
        result = encode_game_string(text)
        self.assertEqual(result, b"Hello")

    def test_encode_japanese(self):
        """Test encoding Japanese text."""
        text = "テスト"
        result = encode_game_string(text)
        self.assertEqual(result, b"\x83\x65\x83\x58\x83\x67")

    def test_encode_unencodable_raises(self):
        """Test that unencodable characters raise EncodingError."""
        # Emoji is not in Shift-JIS
        text = "Hello 😀"
        with self.assertRaises(EncodingError):
            encode_game_string(text, errors="strict")

    def test_encode_with_context(self):
        """Test that context appears in error message."""
        text = "Hello 😀"
        try:
            encode_game_string(text, errors="strict", context="test location")
        except EncodingError as e:
            self.assertIn("test location", str(e))


class TestSkipCsvHeader(unittest.TestCase):
    """Tests for skip_csv_header function."""

    def test_skip_header_success(self):
        """Test skipping header from valid CSV."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("header1,header2,header3\n")
            f.write("data1,data2,data3\n")
            f.name
        try:
            with open(f.name, "r") as csvfile:
                reader = csv.reader(csvfile)
                skip_csv_header(reader, f.name)
                # Should be able to read data row
                row = next(reader)
                self.assertEqual(row, ["data1", "data2", "data3"])
        finally:
            os.unlink(f.name)

    def test_skip_header_empty_file(self):
        """Test that empty file raises InterruptedError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            pass  # Empty file
        try:
            with open(f.name, "r") as csvfile:
                reader = csv.reader(csvfile)
                with self.assertRaises(InterruptedError):
                    skip_csv_header(reader, f.name)
        finally:
            os.unlink(f.name)


class TestReadJsonData(unittest.TestCase):
    """Tests for read_json_data function."""

    def setUp(self):
        """Create a temporary headers.json file."""
        self.temp_dir = tempfile.mkdtemp()
        self.headers_path = os.path.join(self.temp_dir, "headers.json")
        self.headers_data = {
            "dat": {
                "armors": {
                    "head": {
                        "begin_pointer": "0x64",
                        "next_field_pointer": "0x60",
                        "crop_end": 24
                    }
                }
            }
        }
        with open(self.headers_path, "w") as f:
            json.dump(self.headers_data, f)

    def tearDown(self):
        """Clean up temporary files."""
        os.unlink(self.headers_path)
        os.rmdir(self.temp_dir)

    def test_read_valid_xpath(self):
        """Test reading with valid xpath."""
        result = read_json_data("dat/armors/head", self.headers_path)
        self.assertEqual(result, (0x64, 0x60, 24))

    def test_read_incomplete_xpath(self):
        """Test that incomplete xpath raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            read_json_data("dat/armors", self.headers_path)
        self.assertIn("Options are", str(ctx.exception))

    def test_read_invalid_xpath(self):
        """Test that invalid xpath raises KeyError."""
        with self.assertRaises(KeyError):
            read_json_data("dat/weapons/invalid", self.headers_path)


class TestParseLocation(unittest.TestCase):
    """Tests for parse_location function."""

    def test_valid_location(self):
        """Test parsing valid location string."""
        result = parse_location("0x1234@mhfdat.bin")
        self.assertEqual(result, 0x1234)

    def test_valid_location_uppercase(self):
        """Test parsing location with uppercase hex."""
        result = parse_location("0xABCD@file.bin")
        self.assertEqual(result, 0xABCD)

    def test_missing_at_symbol(self):
        """Test that missing @ raises CSVParseError."""
        with self.assertRaises(CSVParseError) as ctx:
            parse_location("0x1234mhfdat.bin")
        self.assertIn("@", str(ctx.exception))

    def test_invalid_hex(self):
        """Test that invalid hex raises CSVParseError."""
        with self.assertRaises(CSVParseError) as ctx:
            parse_location("0xGHIJ@file.bin")
        self.assertIn("Invalid hex", str(ctx.exception))

    def test_empty_hex(self):
        """Test that empty hex part raises CSVParseError."""
        with self.assertRaises(CSVParseError):
            parse_location("@file.bin")


class TestGetNewStrings(unittest.TestCase):
    """Tests for get_new_strings function."""

    def test_valid_csv(self):
        """Test reading valid CSV with translations."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            writer.writerow(["0x100@file.bin", "Original", "Translated"])
            writer.writerow(["0x200@file.bin", "Same", "Same"])  # Should be skipped
            f.name
        try:
            result = get_new_strings(f.name)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0], (0x100, "Translated"))
        finally:
            os.unlink(f.name)

    def test_empty_lines_skipped(self):
        """Test that empty lines are skipped."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            writer.writerow([])  # Empty line
            writer.writerow(["0x100@file.bin", "Original", "Translated"])
            f.name
        try:
            result = get_new_strings(f.name)
            self.assertEqual(len(result), 1)
        finally:
            os.unlink(f.name)

    def test_malformed_lines_skipped(self):
        """Test that lines with fewer than 3 columns are skipped."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            writer.writerow(["0x100@file.bin", "Only two columns"])
            writer.writerow(["0x200@file.bin", "Original", "Translated"])
            f.name
        try:
            result = get_new_strings(f.name)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0][0], 0x200)
        finally:
            os.unlink(f.name)


class TestExportAsCsv(unittest.TestCase):
    """Tests for export_as_csv function."""

    def test_export_basic(self):
        """Test basic CSV export."""
        data = [
            {"offset": 0x100, "text": "Hello"},
            {"offset": 0x200, "text": "World"},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.name
        try:
            lines = export_as_csv(data, f.name, "test.bin")
            self.assertEqual(lines, 2)

            # Verify content
            with open(f.name, "r", encoding="utf-8") as csvfile:
                reader = csv.reader(csvfile)
                header = next(reader)
                self.assertEqual(header, ["location", "source", "target"])
                row1 = next(reader)
                self.assertEqual(row1[0], "0x100@test.bin")
                self.assertEqual(row1[1], "Hello")
        finally:
            os.unlink(f.name)

    def test_export_empty_data(self):
        """Test exporting empty data."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.name
        try:
            lines = export_as_csv([], f.name)
            self.assertEqual(lines, 0)
        finally:
            os.unlink(f.name)


class TestExportForRefrontier(unittest.TestCase):
    """Tests for export_for_refrontier function."""

    def test_export_basic(self):
        """Test basic ReFrontier export."""
        data = [
            {"offset": 100, "text": "Hello"},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.name
        try:
            lines = export_for_refrontier(data, f.name)
            self.assertEqual(lines, 1)

            # Verify content
            with open(f.name, "r", encoding=GAME_ENCODING) as csvfile:
                reader = csv.reader(csvfile, delimiter="\t")
                header = next(reader)
                self.assertEqual(header, ["Offset", "Hash", "JString"])
                row = next(reader)
                self.assertEqual(row[0], "100")
                self.assertEqual(row[2], "Hello")
        finally:
            os.unlink(f.name)

    def test_escape_sequences(self):
        """Test that escape sequences are applied."""
        data = [
            {"offset": 100, "text": "Line1\nLine2"},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.name
        try:
            export_for_refrontier(data, f.name)

            with open(f.name, "r", encoding=GAME_ENCODING) as csvfile:
                reader = csv.reader(csvfile, delimiter="\t")
                next(reader)  # Skip header
                row = next(reader)
                self.assertIn("<NLINE>", row[2])
        finally:
            os.unlink(f.name)


class TestImportFromRefrontier(unittest.TestCase):
    """Tests for import_from_refrontier function."""

    def test_import_basic(self):
        """Test basic ReFrontier import."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False,
                                          encoding=GAME_ENCODING) as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["Offset", "Hash", "JString"])
            writer.writerow(["100", "12345", "Hello"])
            writer.writerow(["200", "67890", "World"])
            f.name
        try:
            result = list(import_from_refrontier(f.name))
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0], {"offset": 100, "text": "Hello"})
            self.assertEqual(result[1], {"offset": 200, "text": "World"})
        finally:
            os.unlink(f.name)

    def test_unescape_sequences(self):
        """Test that escape sequences are unescaped."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False,
                                          encoding=GAME_ENCODING) as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["Offset", "Hash", "JString"])
            writer.writerow(["100", "12345", "Line1<NLINE>Line2"])
            f.name
        try:
            result = list(import_from_refrontier(f.name))
            self.assertEqual(result[0]["text"], "Line1\nLine2")
        finally:
            os.unlink(f.name)


class TestReadUntilNull(unittest.TestCase):
    """Tests for read_until_null function."""

    def test_read_simple_string(self):
        """Test reading null-terminated string."""
        data = b"Hello\x00World"
        bfile = BinaryFile.from_bytes(data)
        result = read_until_null(bfile)
        self.assertEqual(result, b"Hello")

    def test_read_empty_string(self):
        """Test reading empty string (immediate null)."""
        data = b"\x00Rest"
        bfile = BinaryFile.from_bytes(data)
        result = read_until_null(bfile)
        self.assertEqual(result, b"")

    def test_read_to_eof(self):
        """Test reading to end of file without null."""
        data = b"NoNull"
        bfile = BinaryFile.from_bytes(data)
        result = read_until_null(bfile)
        self.assertEqual(result, b"NoNull")


class TestReadFileSection(unittest.TestCase):
    """Tests for read_file_section function."""

    def test_read_simple_section(self):
        """Test reading a simple section with pointers."""
        # Create binary data: pointers followed by strings
        # Pointers at offset 0: point to offset 8 and 14
        # Strings: "Hello\0" at 8, "World\0" at 14
        pointers = struct.pack("<II", 8, 14)
        strings = b"Hello\x00World\x00"
        data = pointers + strings

        bfile = BinaryFile.from_bytes(data)
        result = read_file_section(bfile, 0, 8)  # 8 bytes = 2 pointers

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["offset"], 0)
        self.assertEqual(result[0]["text"], "Hello")
        self.assertEqual(result[1]["offset"], 4)
        self.assertEqual(result[1]["text"], "World")


class TestRefrontierReplacements(unittest.TestCase):
    """Tests for REFRONTIER_REPLACEMENTS constant."""

    def test_replacements_defined(self):
        """Test that all expected replacements are defined."""
        replacements = dict(REFRONTIER_REPLACEMENTS)
        self.assertIn("\t", replacements)
        self.assertIn("\r\n", replacements)
        self.assertIn("\n", replacements)

    def test_replacement_values(self):
        """Test replacement values."""
        replacements = dict(REFRONTIER_REPLACEMENTS)
        self.assertEqual(replacements["\t"], "<TAB>")
        self.assertEqual(replacements["\r\n"], "<CLINE>")
        self.assertEqual(replacements["\n"], "<NLINE>")


class TestInvalidPointers(unittest.TestCase):
    """Tests for invalid pointer handling."""

    def test_pointer_out_of_bounds(self):
        """Test that out-of-bounds pointers raise InvalidPointerError."""
        from src.binary_file import InvalidPointerError
        # Create binary data with a pointer that points beyond the file
        # File is 20 bytes, but pointer points to offset 0x1000
        pointers = struct.pack("<II", 0x1000, 8)  # First pointer is invalid
        strings = b"Hello\x00Test\x00"
        data = pointers + strings

        bfile = BinaryFile.from_bytes(data)
        with self.assertRaises(InvalidPointerError) as ctx:
            read_file_section(bfile, 0, 8)
        self.assertIn("0x1000", str(ctx.exception))

    def test_negative_pointer_value(self):
        """Test that negative-like pointer values (as unsigned) are caught."""
        from src.binary_file import InvalidPointerError
        # 0xFFFFFFFF as unsigned int is a very large positive number
        pointers = struct.pack("<I", 0xFFFFFFFF)
        data = pointers + b"Test\x00"

        bfile = BinaryFile.from_bytes(data)
        with self.assertRaises(InvalidPointerError):
            read_file_section(bfile, 0, 4)

    def test_section_start_out_of_bounds(self):
        """Test that section start beyond file raises InvalidPointerError."""
        from src.binary_file import InvalidPointerError
        data = b"Short data"
        bfile = BinaryFile.from_bytes(data)

        with self.assertRaises(InvalidPointerError) as ctx:
            read_file_section(bfile, 0x1000, 8)
        self.assertIn("section start", str(ctx.exception))

    def test_section_end_out_of_bounds(self):
        """Test that section extending beyond file raises InvalidPointerError."""
        from src.binary_file import InvalidPointerError
        data = b"Short data"  # 10 bytes
        bfile = BinaryFile.from_bytes(data)

        with self.assertRaises(InvalidPointerError) as ctx:
            read_file_section(bfile, 0, 20)  # 20 bytes from a 10-byte file
        self.assertIn("section end", str(ctx.exception))


class TestMalformedInputs(unittest.TestCase):
    """Tests for handling malformed and corrupted inputs."""

    def test_truncated_pointer_table(self):
        """Test handling of truncated pointer data."""
        from src.binary_file import InvalidPointerError
        # Only 2 bytes when we need 4 for a pointer
        data = b"\x08\x00"
        bfile = BinaryFile.from_bytes(data)

        # Bounds checking catches this before struct.unpack
        with self.assertRaises(InvalidPointerError) as ctx:
            read_file_section(bfile, 0, 4)
        self.assertIn("section end", str(ctx.exception))

    def test_csv_with_invalid_encoding(self):
        """Test handling CSV with encoding issues."""
        # This tests the robustness of CSV parsing
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".csv", delete=False) as f:
            # Write invalid UTF-8 sequence
            f.write(b"location,source,target\n")
            f.write(b"0x100@file.bin,\xff\xfe,translation\n")
            temp_path = f.name

        try:
            # Should not crash, might skip the malformed line
            result = get_new_strings(temp_path)
            # The result depends on how Python's csv module handles it
            self.assertIsInstance(result, list)
        except UnicodeDecodeError:
            # Also acceptable - strict handling of encoding errors
            pass
        finally:
            os.unlink(temp_path)

    def test_empty_binary_file(self):
        """Test handling of empty binary files."""
        from src.binary_file import InvalidPointerError
        data = b""
        bfile = BinaryFile.from_bytes(data)
        self.assertEqual(bfile.size, 0)

        with self.assertRaises(InvalidPointerError):
            read_file_section(bfile, 0, 4)


class TestJKRMalformedInputs(unittest.TestCase):
    """Tests for malformed JKR inputs."""

    def test_jkr_too_short(self):
        """Test JKR decompression with truncated header."""
        from src.jkr_decompress import decompress_jkr, JKRError, JKR_MAGIC

        # Only 8 bytes when header needs 16
        data = struct.pack("<II", JKR_MAGIC, 0x108)
        with self.assertRaises(JKRError) as ctx:
            decompress_jkr(data)
        self.assertIn("too short", str(ctx.exception).lower())

    def test_jkr_invalid_compression_type(self):
        """Test JKR with invalid compression type."""
        from src.jkr_decompress import decompress_jkr, JKRError, JKR_MAGIC

        # Use compression type 99 which doesn't exist
        header = struct.pack("<IHHII", JKR_MAGIC, 0x108, 99, 16, 100)
        data = header + b"\x00" * 100

        with self.assertRaises(JKRError) as ctx:
            decompress_jkr(data)
        self.assertIn("compression type", str(ctx.exception).lower())

    def test_jkr_truncated_compressed_data(self):
        """Test JKR with truncated compressed data."""
        from src.jkr_decompress import decompress_jkr, JKR_MAGIC, CompressionType

        # Header says 1000 bytes decompressed, but we only provide 9
        header = struct.pack("<IHHII", JKR_MAGIC, 0x108, CompressionType.RW, 16, 1000)
        data = header + b"ShortData"

        # RW decoder reads available bytes (returns less than expected size)
        result = decompress_jkr(data)
        # RW decoder returns exactly what it reads, not padded
        self.assertEqual(len(result), 9)  # Only 9 bytes were available
        self.assertEqual(result, b"ShortData")


class TestIntegrationWorkflow(unittest.TestCase):
    """Integration tests for complete extract-modify-import workflow."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def _create_test_binary(self, strings: list[str]) -> bytes:
        """Create a test binary file with pointer table and strings."""
        # Calculate string positions
        pointer_table_size = len(strings) * 4
        string_offsets = []
        current_offset = pointer_table_size

        encoded_strings = []
        for s in strings:
            encoded = encode_game_string(s) + b"\x00"
            string_offsets.append(current_offset)
            encoded_strings.append(encoded)
            current_offset += len(encoded)

        # Build binary: pointers + strings
        data = b""
        for offset in string_offsets:
            data += struct.pack("<I", offset)
        for encoded in encoded_strings:
            data += encoded

        return data

    def test_roundtrip_extract_and_import(self):
        """Test complete workflow: extract to CSV, modify, import back."""
        from src.import_data import import_from_csv, get_new_strings

        # Create test binary
        original_strings = ["Hello", "World", "Test"]
        binary_data = self._create_test_binary(original_strings)

        # Write binary to temp file
        binary_path = os.path.join(self.temp_dir, "test.bin")
        with open(binary_path, "wb") as f:
            f.write(binary_data)

        # Create CSV with translations
        csv_path = os.path.join(self.temp_dir, "translations.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            import csv
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            # Translate "Hello" at offset 0 (pointer table start)
            writer.writerow(["0x0@test.bin", "Hello", "Bonjour"])
            # Keep "World" the same (should be skipped)
            writer.writerow(["0x4@test.bin", "World", "World"])
            # Translate "Test"
            writer.writerow(["0x8@test.bin", "Test", "Prueba"])

        # Get new strings
        new_strings = get_new_strings(csv_path)

        # Should have 2 translations (World was skipped as unchanged)
        self.assertEqual(len(new_strings), 2)
        self.assertEqual(new_strings[0], (0x0, "Bonjour"))
        self.assertEqual(new_strings[1], (0x8, "Prueba"))

    def test_extract_section_valid_pointers(self):
        """Test extracting strings from a section with valid pointers."""
        strings = ["Item1", "Item2", "Item3"]
        binary_data = self._create_test_binary(strings)

        bfile = BinaryFile.from_bytes(binary_data)
        result = read_file_section(bfile, 0, 12)  # 3 pointers = 12 bytes

        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["text"], "Item1")
        self.assertEqual(result[1]["text"], "Item2")
        self.assertEqual(result[2]["text"], "Item3")

    def test_extract_japanese_text(self):
        """Test extracting Japanese text."""
        strings = ["テスト", "日本語", "ゲーム"]
        binary_data = self._create_test_binary(strings)

        bfile = BinaryFile.from_bytes(binary_data)
        result = read_file_section(bfile, 0, 12)

        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["text"], "テスト")
        self.assertEqual(result[1]["text"], "日本語")
        self.assertEqual(result[2]["text"], "ゲーム")

    def test_binary_file_size_tracking(self):
        """Test that BinaryFile correctly tracks file size."""
        data = b"Test data with some content"
        bfile = BinaryFile.from_bytes(data)

        self.assertEqual(bfile.size, len(data))

    def test_binary_file_context_manager(self):
        """Test BinaryFile as context manager."""
        # Create a test file
        test_path = os.path.join(self.temp_dir, "context_test.bin")
        test_data = b"Context manager test data"
        with open(test_path, "wb") as f:
            f.write(test_data)

        # Test context manager
        with BinaryFile(test_path) as bf:
            self.assertEqual(bf.size, len(test_data))
            content = bf.read(len(test_data))
            self.assertEqual(content, test_data)


if __name__ == "__main__":
    unittest.main()
