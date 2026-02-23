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
    encode_ecd,
    compress_jkr_hfi,
)
from src.common import (
    skip_csv_header,
    read_json_data,
    read_until_null,
    read_file_section,
    read_multi_pointer_entries,
    read_struct_strings,
    read_quest_table,
    read_extraction_config,
    extract_text_data,
    load_file_data,
    get_all_xpaths,
    _is_extraction_leaf,
    _read_indirect_count,
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

    def test_import_auto_decrypts_ecd_source(self):
        """Test that import_from_csv auto-decrypts ECD-encrypted source files."""
        from src.import_data import import_from_csv

        # Create test binary and encrypt it
        original_strings = ["Hello", "World", "Test"]
        binary_data = self._create_test_binary(original_strings)
        encrypted_data = encode_ecd(binary_data)

        # Write encrypted binary to temp file
        binary_path = os.path.join(self.temp_dir, "encrypted.bin")
        with open(binary_path, "wb") as f:
            f.write(encrypted_data)

        # Create CSV with a translation
        csv_path = os.path.join(self.temp_dir, "translations.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            writer.writerow(["0x0@encrypted.bin", "Hello", "Bonjour"])

        # Import should auto-decrypt and produce valid output
        output_path = os.path.join(self.temp_dir, "output.bin")
        result = import_from_csv(csv_path, binary_path, output_path=output_path)

        self.assertIsNotNone(result)
        with open(output_path, "rb") as f:
            output_data = f.read()

        # Output should NOT be encrypted (no ECD header)
        self.assertNotEqual(output_data[:4], b"ecd\x1a")

        # Verify the translation was written: read pointer at offset 0,
        # follow it, and check the string
        pointer = struct.unpack("<I", output_data[0:4])[0]
        # The new pointer should point to appended data at end of original binary
        self.assertGreaterEqual(pointer, len(binary_data))
        # Read null-terminated string at pointer offset
        end = output_data.index(b"\x00", pointer)
        translated = output_data[pointer:end]
        self.assertEqual(translated, encode_game_string("Bonjour"))

    def test_import_auto_decompresses_jkr_source(self):
        """Test that import_from_csv auto-decompresses JPK-compressed source files."""
        from src.import_data import import_from_csv

        # Create test binary and compress it
        original_strings = ["Hello", "World", "Test"]
        binary_data = self._create_test_binary(original_strings)
        compressed_data = compress_jkr_hfi(binary_data)

        # Write compressed binary to temp file
        binary_path = os.path.join(self.temp_dir, "compressed.bin")
        with open(binary_path, "wb") as f:
            f.write(compressed_data)

        # Create CSV with a translation
        csv_path = os.path.join(self.temp_dir, "translations.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            writer.writerow(["0x0@compressed.bin", "Hello", "Bonjour"])

        # Import should auto-decompress and produce valid output
        output_path = os.path.join(self.temp_dir, "output.bin")
        result = import_from_csv(csv_path, binary_path, output_path=output_path)

        self.assertIsNotNone(result)
        with open(output_path, "rb") as f:
            output_data = f.read()

        # Output should NOT be compressed (no JKR header)
        self.assertNotEqual(output_data[:4], b"JKR\x1a")

        # Verify the translation was written
        pointer = struct.unpack("<I", output_data[0:4])[0]
        self.assertGreaterEqual(pointer, len(binary_data))
        end = output_data.index(b"\x00", pointer)
        translated = output_data[pointer:end]
        self.assertEqual(translated, encode_game_string("Bonjour"))

    def test_import_auto_decrypts_and_decompresses(self):
        """Test that import_from_csv handles encrypted+compressed source files."""
        from src.import_data import import_from_csv

        # Create test binary, compress, then encrypt (game format)
        original_strings = ["Alpha", "Beta", "Gamma"]
        binary_data = self._create_test_binary(original_strings)
        compressed_data = compress_jkr_hfi(binary_data)
        encrypted_data = encode_ecd(compressed_data)

        # Write encrypted+compressed binary to temp file
        binary_path = os.path.join(self.temp_dir, "game_file.bin")
        with open(binary_path, "wb") as f:
            f.write(encrypted_data)

        # Create CSV with translations
        csv_path = os.path.join(self.temp_dir, "translations.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            writer.writerow(["0x0@game_file.bin", "Alpha", "Premier"])
            writer.writerow(["0x8@game_file.bin", "Gamma", "Troisieme"])

        # Import should auto-decrypt then auto-decompress
        output_path = os.path.join(self.temp_dir, "output.bin")
        result = import_from_csv(csv_path, binary_path, output_path=output_path)

        self.assertIsNotNone(result)
        with open(output_path, "rb") as f:
            output_data = f.read()

        # Output should be plain binary (not encrypted, not compressed)
        self.assertNotEqual(output_data[:4], b"ecd\x1a")
        self.assertNotEqual(output_data[:4], b"JKR\x1a")

        # Verify both translations were written
        pointer_0 = struct.unpack("<I", output_data[0:4])[0]
        end_0 = output_data.index(b"\x00", pointer_0)
        self.assertEqual(output_data[pointer_0:end_0], encode_game_string("Premier"))

        pointer_8 = struct.unpack("<I", output_data[8:12])[0]
        end_8 = output_data.index(b"\x00", pointer_8)
        self.assertEqual(output_data[pointer_8:end_8], encode_game_string("Troisieme"))

        # Verify untouched pointer still works (Beta at offset 4)
        pointer_4 = struct.unpack("<I", output_data[4:8])[0]
        end_4 = output_data.index(b"\x00", pointer_4)
        self.assertEqual(output_data[pointer_4:end_4], encode_game_string("Beta"))

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


class TestGetAllXpaths(unittest.TestCase):
    """Tests for get_all_xpaths function."""

    def setUp(self):
        """Create a temporary headers.json file."""
        self.temp_dir = tempfile.mkdtemp()
        self.headers_path = os.path.join(self.temp_dir, "headers.json")

    def tearDown(self):
        """Clean up temporary files."""
        if os.path.exists(self.headers_path):
            os.unlink(self.headers_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_get_xpaths_simple(self):
        """Test getting xpaths from simple structure."""
        headers_data = {
            "dat": {
                "armors": {
                    "head": {
                        "begin_pointer": "0x64",
                        "next_field_pointer": "0x60"
                    }
                }
            }
        }
        with open(self.headers_path, "w") as f:
            json.dump(headers_data, f)

        result = get_all_xpaths(self.headers_path)
        self.assertEqual(result, ["dat/armors/head"])

    def test_get_xpaths_nested(self):
        """Test getting xpaths from nested structure."""
        headers_data = {
            "dat": {
                "weapons": {
                    "melee": {
                        "name": {
                            "begin_pointer": "0x88",
                            "next_field_pointer": "0x174"
                        },
                        "description": {
                            "begin_pointer": "0x8C",
                            "next_field_pointer": "0x40"
                        }
                    }
                },
                "armors": {
                    "head": {
                        "begin_pointer": "0x64",
                        "next_field_pointer": "0x60"
                    }
                }
            }
        }
        with open(self.headers_path, "w") as f:
            json.dump(headers_data, f)

        result = get_all_xpaths(self.headers_path)
        self.assertEqual(len(result), 3)
        self.assertIn("dat/armors/head", result)
        self.assertIn("dat/weapons/melee/name", result)
        self.assertIn("dat/weapons/melee/description", result)

    def test_get_xpaths_skips_comments(self):
        """Test that comment fields are skipped."""
        headers_data = {
            "dat": {
                "_comment": "This is a comment",
                "items": {
                    "name": {
                        "begin_pointer": "0x100",
                        "next_field_pointer": "0xFC"
                    }
                }
            }
        }
        with open(self.headers_path, "w") as f:
            json.dump(headers_data, f)

        result = get_all_xpaths(self.headers_path)
        self.assertEqual(result, ["dat/items/name"])

    def test_get_xpaths_empty_section(self):
        """Test handling of empty sections."""
        headers_data = {
            "inf": {
                "_comment": "Quest data - empty"
            }
        }
        with open(self.headers_path, "w") as f:
            json.dump(headers_data, f)

        result = get_all_xpaths(self.headers_path)
        self.assertEqual(result, [])

    def test_get_xpaths_real_headers(self):
        """Test with the real headers.json file."""
        result = get_all_xpaths(DEFAULT_HEADERS_PATH)
        # Should have multiple xpaths from the real file
        self.assertGreater(len(result), 5)
        # Check some expected xpaths exist
        self.assertIn("dat/armors/head", result)
        self.assertIn("dat/weapons/melee/name", result)


class TestIsExtractionLeaf(unittest.TestCase):
    """Tests for _is_extraction_leaf function."""

    def test_standard_format(self):
        """Test standard pointer-pair format is detected."""
        config = {"begin_pointer": "0x64", "next_field_pointer": "0x60"}
        self.assertTrue(_is_extraction_leaf(config))

    def test_count_based_format(self):
        """Test count-based format is detected."""
        config = {"begin_pointer": "0x0C", "count_pointer": "0x10"}
        self.assertTrue(_is_extraction_leaf(config))

    def test_strided_format(self):
        """Test struct-strided format is detected."""
        config = {
            "begin_pointer": "0x00",
            "entry_count": 24,
            "entry_size": 56,
            "field_offset": 48
        }
        self.assertTrue(_is_extraction_leaf(config))

    def test_indirect_count_format(self):
        """Test indirect count format is detected."""
        config = {
            "begin_pointer": "0x134",
            "count_base_pointer": "0x010",
            "count_offset": "0x22",
            "count_type": "u16"
        }
        self.assertTrue(_is_extraction_leaf(config))

    def test_null_terminated_format(self):
        """Test null-terminated format is detected."""
        config = {
            "begin_pointer": "0x078",
            "null_terminated": True,
            "pointers_per_entry": 4
        }
        self.assertTrue(_is_extraction_leaf(config))

    def test_null_terminated_false_not_leaf(self):
        """Test that null_terminated=False is not detected as leaf."""
        config = {"begin_pointer": "0x078", "null_terminated": False}
        self.assertFalse(_is_extraction_leaf(config))

    def test_quest_table_format(self):
        """Test quest table format is detected."""
        config = {
            "begin_pointer": "0x14",
            "quest_table": True,
            "count_base_pointer": "0x10",
            "count_offset": "0x00",
        }
        self.assertTrue(_is_extraction_leaf(config))

    def test_indirect_count_strided_format(self):
        """Test indirect count + strided format is detected."""
        config = {
            "begin_pointer": "0x168",
            "count_base_pointer": "0x010",
            "count_offset": "0x4E",
            "count_type": "u16",
            "count_adjust": 1,
            "entry_size": 20,
            "field_offset": 0,
        }
        self.assertTrue(_is_extraction_leaf(config))

    def test_missing_begin_pointer(self):
        """Test that missing begin_pointer returns False."""
        config = {"next_field_pointer": "0x60"}
        self.assertFalse(_is_extraction_leaf(config))

    def test_comment_only(self):
        """Test that comment-only node returns False."""
        config = {"_comment": "Some data."}
        self.assertFalse(_is_extraction_leaf(config))


class TestReadStructStrings(unittest.TestCase):
    """Tests for read_struct_strings function."""

    def _build_struct_binary(self, strings: list[str], entry_size: int, field_offset: int) -> bytes:
        """Build a binary with struct entries containing string pointers."""
        entry_count = len(strings)
        # Layout: struct array first, then strings
        struct_array_size = entry_count * entry_size
        encoded = []
        string_offsets = []
        current_offset = struct_array_size
        for s in strings:
            enc = encode_game_string(s) + b"\x00"
            string_offsets.append(current_offset)
            encoded.append(enc)
            current_offset += len(enc)

        # Build struct array
        data = bytearray(struct_array_size)
        for i, offset in enumerate(string_offsets):
            pos = i * entry_size + field_offset
            struct.pack_into("<I", data, pos, offset)

        # Append string data
        for enc in encoded:
            data.extend(enc)

        return bytes(data)

    def test_read_basic_structs(self):
        """Test reading strings from simple struct array."""
        binary = self._build_struct_binary(
            ["Title A", "Title B", "Title C"],
            entry_size=16, field_offset=8
        )
        bfile = BinaryFile.from_bytes(binary)
        result = read_struct_strings(bfile, 0, 3, 16, 8)

        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["text"], "Title A")
        self.assertEqual(result[1]["text"], "Title B")
        self.assertEqual(result[2]["text"], "Title C")

    def test_read_with_large_stride(self):
        """Test reading with stride matching mhfjmp menu entry size (56 bytes)."""
        binary = self._build_struct_binary(
            ["Menu 1", "Menu 2"],
            entry_size=56, field_offset=48
        )
        bfile = BinaryFile.from_bytes(binary)
        result = read_struct_strings(bfile, 0, 2, 56, 48)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["text"], "Menu 1")
        self.assertEqual(result[0]["offset"], 48)
        self.assertEqual(result[1]["text"], "Menu 2")
        self.assertEqual(result[1]["offset"], 56 + 48)

    def test_read_skips_null_pointers(self):
        """Test that null string pointers are skipped."""
        # Build with 3 entries, but middle one has null pointer
        binary = self._build_struct_binary(
            ["First", "Second", "Third"],
            entry_size=16, field_offset=8
        )
        # Zero out the middle entry's pointer
        data = bytearray(binary)
        struct.pack_into("<I", data, 1 * 16 + 8, 0)
        bfile = BinaryFile.from_bytes(bytes(data))
        result = read_struct_strings(bfile, 0, 3, 16, 8)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["text"], "First")
        self.assertEqual(result[1]["text"], "Third")

    def test_read_japanese_structs(self):
        """Test reading Japanese text from structs."""
        binary = self._build_struct_binary(
            ["塔", "砂漠"],
            entry_size=12, field_offset=4
        )
        bfile = BinaryFile.from_bytes(binary)
        result = read_struct_strings(bfile, 0, 2, 12, 4)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["text"], "塔")
        self.assertEqual(result[1]["text"], "砂漠")


class TestCountBasedExtraction(unittest.TestCase):
    """Tests for count-based pointer table extraction via extract_text_data."""

    def _build_count_based_binary(self, strings: list[str]) -> bytes:
        """
        Build a binary with a file header pointing to a string pointer array.

        Layout:
        - 0x00-0x03: padding (unused header field)
        - 0x04-0x07: padding
        - 0x08-0x0B: padding
        - 0x0C-0x0F: pointer to string pointer array
        - 0x10-0x13: count of strings
        - 0x14+: string pointer array, then actual strings
        """
        header_size = 0x14
        pointer_array_start = header_size
        pointer_array_size = len(strings) * 4
        strings_start = pointer_array_start + pointer_array_size

        # Encode strings and compute offsets
        encoded = []
        string_offsets = []
        current = strings_start
        for s in strings:
            enc = encode_game_string(s) + b"\x00"
            string_offsets.append(current)
            encoded.append(enc)
            current += len(enc)

        # Build file
        data = bytearray(header_size)
        # Write pointer to array at 0x0C
        struct.pack_into("<I", data, 0x0C, pointer_array_start)
        # Write count at 0x10
        struct.pack_into("<I", data, 0x10, len(strings))

        # Pointer array
        for offset in string_offsets:
            data.extend(struct.pack("<I", offset))
        # Actual strings
        for enc in encoded:
            data.extend(enc)

        return bytes(data)

    def test_count_based_extraction(self):
        """Test extracting strings using count-based pointer table."""
        binary = self._build_count_based_binary(["Alpha", "Beta", "Gamma"])

        # Write to temp file and extract
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x0C",
                "count_pointer": "0x10"
            }
            result = extract_text_data(temp_path, config)

            self.assertEqual(len(result), 3)
            self.assertEqual(result[0]["text"], "Alpha")
            self.assertEqual(result[1]["text"], "Beta")
            self.assertEqual(result[2]["text"], "Gamma")
        finally:
            os.unlink(temp_path)

    def test_count_based_empty(self):
        """Test count-based extraction with zero entries."""
        # Need extra byte so pointer 0x14 is within bounds for read_file_section
        data = bytearray(0x18)
        struct.pack_into("<I", data, 0x0C, 0x14)  # pointer to array at 0x14
        struct.pack_into("<I", data, 0x10, 0)       # zero count

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(bytes(data))
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x0C",
                "count_pointer": "0x10"
            }
            result = extract_text_data(temp_path, config)
            self.assertEqual(len(result), 0)
        finally:
            os.unlink(temp_path)


class TestStridedExtraction(unittest.TestCase):
    """Tests for struct-strided extraction via extract_text_data."""

    def _build_strided_binary(
        self, strings: list[str], entry_size: int, field_offset: int
    ) -> bytes:
        """
        Build a binary with a header pointer to a struct array.

        Layout:
        - 0x00-0x03: pointer to struct array
        - 0x04+: struct array, then strings
        """
        header_size = 4
        array_start = header_size
        array_size = len(strings) * entry_size
        strings_start = array_start + array_size

        encoded = []
        string_offsets = []
        current = strings_start
        for s in strings:
            enc = encode_game_string(s) + b"\x00"
            string_offsets.append(current)
            encoded.append(enc)
            current += len(enc)

        data = bytearray(header_size)
        struct.pack_into("<I", data, 0x00, array_start)

        # Build struct array
        array_data = bytearray(array_size)
        for i, offset in enumerate(string_offsets):
            struct.pack_into("<I", array_data, i * entry_size + field_offset, offset)
        data.extend(array_data)

        for enc in encoded:
            data.extend(enc)

        return bytes(data)

    def test_strided_extraction(self):
        """Test extracting strings from struct-strided format."""
        binary = self._build_strided_binary(
            ["Tower", "Desert", "Forest"],
            entry_size=56, field_offset=48
        )

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x00",
                "entry_count": 3,
                "entry_size": 56,
                "field_offset": 48
            }
            result = extract_text_data(temp_path, config)

            self.assertEqual(len(result), 3)
            self.assertEqual(result[0]["text"], "Tower")
            self.assertEqual(result[1]["text"], "Desert")
            self.assertEqual(result[2]["text"], "Forest")
        finally:
            os.unlink(temp_path)


class TestReadExtractionConfig(unittest.TestCase):
    """Tests for read_extraction_config function."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.headers_path = os.path.join(self.temp_dir, "headers.json")

    def tearDown(self):
        os.unlink(self.headers_path)
        os.rmdir(self.temp_dir)

    def test_standard_config(self):
        """Test reading standard pointer-pair config."""
        headers = {
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
            json.dump(headers, f)

        result = read_extraction_config("dat/armors/head", self.headers_path)
        self.assertEqual(result["begin_pointer"], "0x64")
        self.assertEqual(result["next_field_pointer"], "0x60")
        self.assertEqual(result["crop_end"], 24)

    def test_count_based_config(self):
        """Test reading count-based config."""
        headers = {
            "jmp": {
                "strings": {
                    "begin_pointer": "0x0C",
                    "count_pointer": "0x10"
                }
            }
        }
        with open(self.headers_path, "w") as f:
            json.dump(headers, f)

        result = read_extraction_config("jmp/strings", self.headers_path)
        self.assertEqual(result["begin_pointer"], "0x0C")
        self.assertEqual(result["count_pointer"], "0x10")

    def test_strided_config(self):
        """Test reading struct-strided config."""
        headers = {
            "jmp": {
                "menu": {
                    "title": {
                        "begin_pointer": "0x00",
                        "entry_count": 24,
                        "entry_size": 56,
                        "field_offset": 48
                    }
                }
            }
        }
        with open(self.headers_path, "w") as f:
            json.dump(headers, f)

        result = read_extraction_config("jmp/menu/title", self.headers_path)
        self.assertEqual(result["entry_count"], 24)
        self.assertEqual(result["entry_size"], 56)
        self.assertEqual(result["field_offset"], 48)

    def test_incomplete_xpath_raises(self):
        """Test that incomplete xpath raises ValueError."""
        headers = {
            "jmp": {
                "menu": {
                    "title": {
                        "begin_pointer": "0x00",
                        "entry_count": 24,
                        "entry_size": 56,
                        "field_offset": 48
                    },
                    "description": {
                        "begin_pointer": "0x00",
                        "entry_count": 24,
                        "entry_size": 56,
                        "field_offset": 52
                    }
                }
            }
        }
        with open(self.headers_path, "w") as f:
            json.dump(headers, f)

        with self.assertRaises(ValueError) as ctx:
            read_extraction_config("jmp/menu", self.headers_path)
        self.assertIn("title", str(ctx.exception))


class TestGetAllXpathsNewFormats(unittest.TestCase):
    """Tests for get_all_xpaths with new extraction formats."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.headers_path = os.path.join(self.temp_dir, "headers.json")

    def tearDown(self):
        os.unlink(self.headers_path)
        os.rmdir(self.temp_dir)

    def test_detects_count_based(self):
        """Test that count-based entries are found."""
        headers = {
            "jmp": {
                "strings": {
                    "begin_pointer": "0x0C",
                    "count_pointer": "0x10"
                }
            }
        }
        with open(self.headers_path, "w") as f:
            json.dump(headers, f)

        result = get_all_xpaths(self.headers_path)
        self.assertIn("jmp/strings", result)

    def test_detects_strided(self):
        """Test that struct-strided entries are found."""
        headers = {
            "jmp": {
                "menu": {
                    "title": {
                        "begin_pointer": "0x00",
                        "entry_count": 24,
                        "entry_size": 56,
                        "field_offset": 48
                    }
                }
            }
        }
        with open(self.headers_path, "w") as f:
            json.dump(headers, f)

        result = get_all_xpaths(self.headers_path)
        self.assertIn("jmp/menu/title", result)

    def test_mixed_formats(self):
        """Test that all three formats are detected together."""
        headers = {
            "dat": {
                "items": {
                    "name": {
                        "begin_pointer": "0x100",
                        "next_field_pointer": "0xFC"
                    }
                }
            },
            "jmp": {
                "_comment": "Jump data.",
                "menu": {
                    "title": {
                        "begin_pointer": "0x00",
                        "entry_count": 24,
                        "entry_size": 56,
                        "field_offset": 48
                    }
                },
                "strings": {
                    "begin_pointer": "0x0C",
                    "count_pointer": "0x10"
                }
            }
        }
        with open(self.headers_path, "w") as f:
            json.dump(headers, f)

        result = get_all_xpaths(self.headers_path)
        self.assertEqual(len(result), 3)
        self.assertIn("dat/items/name", result)
        self.assertIn("jmp/menu/title", result)
        self.assertIn("jmp/strings", result)

    def test_real_headers_includes_jmp(self):
        """Test that the real headers.json now includes jmp xpaths."""
        # Write a dummy file so tearDown doesn't fail
        with open(self.headers_path, "w") as f:
            json.dump({}, f)

        result = get_all_xpaths(DEFAULT_HEADERS_PATH)
        self.assertIn("jmp/menu/title", result)
        self.assertIn("jmp/menu/description", result)
        self.assertIn("jmp/strings", result)

    def test_real_headers_includes_new_dat_targets(self):
        """Test that the real headers.json includes all mhfdat extraction targets."""
        with open(self.headers_path, "w") as f:
            json.dump({}, f)

        result = get_all_xpaths(DEFAULT_HEADERS_PATH)
        self.assertIn("dat/monsters/description", result)
        self.assertIn("dat/items/source", result)
        self.assertIn("dat/equipment/description", result)
        self.assertIn("dat/weapons/ranged/name", result)
        self.assertIn("dat/weapons/ranged/description", result)
        self.assertIn("dat/ranks/label", result)
        self.assertIn("dat/ranks/requirement", result)
        self.assertIn("dat/hunting_horn/guide", result)
        self.assertIn("dat/hunting_horn/tutorial", result)
        self.assertIn("inf/quests", result)
        # Old flat ranged xpath should no longer exist
        self.assertNotIn("dat/weapons/ranged", result)


class TestIndirectCountExtraction(unittest.TestCase):
    """Tests for indirect count extraction via extract_text_data."""

    def _build_indirect_count_binary(
        self, strings: list[str], pointers_per_entry: int = 1
    ) -> bytes:
        """
        Build a binary with indirect count extraction layout.

        Layout:
        - 0x00-0x03: pointer to count table (points to 0x10)
        - 0x04-0x07: pointer to string pointer array
        - 0x08-0x0F: padding
        - 0x10-0x11: count value (u16) at count table + 0x00
        - 0x12-0x13: padding
        - 0x14+: string pointer array, then actual strings
        """
        header_size = 0x14
        pointer_array_start = header_size
        count = len(strings)
        pointer_array_size = count * pointers_per_entry * 4
        strings_start = pointer_array_start + pointer_array_size

        encoded = []
        string_offsets = []
        current = strings_start
        for s in strings:
            enc = encode_game_string(s) + b"\x00"
            string_offsets.append(current)
            encoded.append(enc)
            current += len(enc)

        data = bytearray(header_size)
        # 0x00: pointer to count table (points to 0x10)
        struct.pack_into("<I", data, 0x00, 0x10)
        # 0x04: pointer to string pointer array
        struct.pack_into("<I", data, 0x04, pointer_array_start)
        # 0x10: count as u16
        struct.pack_into("<H", data, 0x10, count)

        # Pointer array
        for offset in string_offsets:
            data.extend(struct.pack("<I", offset))
        # Pad remaining pointer slots with zeros for multi-pointer entries
        zero_slots = count * pointers_per_entry - count
        for _ in range(zero_slots):
            data.extend(struct.pack("<I", 0))
        # Actual strings
        for enc in encoded:
            data.extend(enc)

        return bytes(data)

    def _build_indirect_count_binary_multi(
        self, groups: list[list[str]]
    ) -> bytes:
        """
        Build a binary with s32px4 indirect count layout.

        Each group has 4 string pointers (some may be None for zero).
        Groups are separated by a zero pointer as the first of 4.
        """
        pointers_per_entry = 4
        header_size = 0x14
        count = len(groups)
        pointer_array_start = header_size
        pointer_array_size = count * pointers_per_entry * 4

        # Collect all non-None strings and assign offsets
        all_strings = []
        string_map: dict[int, int] = {}  # index in flat list -> file offset
        current_offset = pointer_array_start + pointer_array_size
        for group in groups:
            for s in group:
                if s is not None:
                    enc = encode_game_string(s) + b"\x00"
                    string_map[len(all_strings)] = current_offset
                    all_strings.append(enc)
                    current_offset += len(enc)

        data = bytearray(header_size)
        struct.pack_into("<I", data, 0x00, 0x10)  # count table pointer
        struct.pack_into("<I", data, 0x04, pointer_array_start)  # array pointer
        struct.pack_into("<H", data, 0x10, count)  # count

        # Build pointer array
        str_idx = 0
        for group in groups:
            for s in group:
                if s is not None:
                    data.extend(struct.pack("<I", string_map[str_idx]))
                    str_idx += 1
                else:
                    data.extend(struct.pack("<I", 0))

        # Append strings
        for enc in all_strings:
            data.extend(enc)

        return bytes(data)

    def test_indirect_count_simple(self):
        """Test indirect count extraction with simple s32p array."""
        binary = self._build_indirect_count_binary(["Alpha", "Beta", "Gamma"])

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x04",
                "count_base_pointer": "0x00",
                "count_offset": "0x00",
                "count_type": "u16"
            }
            result = extract_text_data(temp_path, config)

            self.assertEqual(len(result), 3)
            self.assertEqual(result[0]["text"], "Alpha")
            self.assertEqual(result[1]["text"], "Beta")
            self.assertEqual(result[2]["text"], "Gamma")
        finally:
            os.unlink(temp_path)

    def test_indirect_count_zero(self):
        """Test indirect count extraction with zero count."""
        data = bytearray(0x18)
        struct.pack_into("<I", data, 0x00, 0x10)  # count table at 0x10
        struct.pack_into("<I", data, 0x04, 0x14)  # array at 0x14
        struct.pack_into("<H", data, 0x10, 0)      # count = 0

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(bytes(data))
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x04",
                "count_base_pointer": "0x00",
                "count_offset": "0x00",
                "count_type": "u16"
            }
            result = extract_text_data(temp_path, config)
            self.assertEqual(len(result), 0)
        finally:
            os.unlink(temp_path)

    def test_indirect_count_with_pointers_per_entry(self):
        """Test indirect count with pointers_per_entry=4 (s32px4)."""
        # 2 entries, each with 4 pointers. Zero pointers separate groups.
        groups = [
            ["Desc1a", "Desc1b", None, None],
            ["Desc2a", None, "Desc2c", None],
        ]
        binary = self._build_indirect_count_binary_multi(groups)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x04",
                "count_base_pointer": "0x00",
                "count_offset": "0x00",
                "count_type": "u16",
                "pointers_per_entry": 4
            }
            result = extract_text_data(temp_path, config)

            # With s32px4, zero pointers act as separators for join_lines
            # We should get grouped results
            self.assertGreater(len(result), 0)
            # All non-None strings should appear in results
            all_text = " ".join(r["text"] for r in result)
            self.assertIn("Desc1a", all_text)
            self.assertIn("Desc1b", all_text)
            self.assertIn("Desc2a", all_text)
            self.assertIn("Desc2c", all_text)
        finally:
            os.unlink(temp_path)


class TestIndirectCountStridedExtraction(unittest.TestCase):
    """Tests for indirect-count strided extraction (rank labels)."""

    def _build_indirect_count_strided_binary(
        self, string_pairs: list[tuple[str, str]],
        entry_size: int = 20
    ) -> bytes:
        """
        Build a binary with indirect count + strided struct layout.

        Layout:
        - 0x00-0x03: pointer to count table (points to 0x10)
        - 0x04-0x07: pointer to struct array
        - 0x08-0x0F: padding
        - 0x10-0x11: count value (u16), stored as count - 1 (needs +1 adjust)
        - 0x12-0x13: padding
        - 0x14+: struct array (2 s32p + 12 padding per entry), then strings
        """
        header_size = 0x14
        array_start = header_size
        count = len(string_pairs)
        array_size = count * entry_size
        strings_start = array_start + array_size

        encoded = []
        string_offsets = []
        current = strings_start
        for s1, s2 in string_pairs:
            enc1 = encode_game_string(s1) + b"\x00"
            enc2 = encode_game_string(s2) + b"\x00"
            string_offsets.append((current, current + len(enc1)))
            encoded.extend([enc1, enc2])
            current += len(enc1) + len(enc2)

        data = bytearray(header_size)
        struct.pack_into("<I", data, 0x00, 0x10)  # count table pointer
        struct.pack_into("<I", data, 0x04, array_start)  # array pointer
        struct.pack_into("<H", data, 0x10, count - 1)  # count - 1 (needs adjust)

        # Build struct array
        for i, (off1, off2) in enumerate(string_offsets):
            entry = bytearray(entry_size)
            struct.pack_into("<I", entry, 0, off1)
            struct.pack_into("<I", entry, 4, off2)
            data.extend(entry)

        for enc in encoded:
            data.extend(enc)

        return bytes(data)

    def test_strided_field_0(self):
        """Test extracting first string field from strided structs."""
        pairs = [("HR1+", "HR1~"), ("HR2+", "HR2~"), ("HR3+", "HR3~")]
        binary = self._build_indirect_count_strided_binary(pairs)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x04",
                "count_base_pointer": "0x00",
                "count_offset": "0x00",
                "count_type": "u16",
                "count_adjust": 1,
                "entry_size": 20,
                "field_offset": 0,
            }
            result = extract_text_data(temp_path, config)

            self.assertEqual(len(result), 3)
            self.assertEqual(result[0]["text"], "HR1+")
            self.assertEqual(result[1]["text"], "HR2+")
            self.assertEqual(result[2]["text"], "HR3+")
        finally:
            os.unlink(temp_path)

    def test_strided_field_4(self):
        """Test extracting second string field from strided structs."""
        pairs = [("HR1+", "HR1~"), ("HR2+", "HR2~")]
        binary = self._build_indirect_count_strided_binary(pairs)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x04",
                "count_base_pointer": "0x00",
                "count_offset": "0x00",
                "count_type": "u16",
                "count_adjust": 1,
                "entry_size": 20,
                "field_offset": 4,
            }
            result = extract_text_data(temp_path, config)

            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["text"], "HR1~")
            self.assertEqual(result[1]["text"], "HR2~")
        finally:
            os.unlink(temp_path)

    def test_strided_zero_count(self):
        """Test indirect count strided with zero count (after adjust)."""
        # count_adjust=0, stored count=0 → 0 entries
        data = bytearray(0x18)
        struct.pack_into("<I", data, 0x00, 0x10)
        struct.pack_into("<I", data, 0x04, 0x14)
        struct.pack_into("<H", data, 0x10, 0)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(bytes(data))
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x04",
                "count_base_pointer": "0x00",
                "count_offset": "0x00",
                "count_type": "u16",
                "entry_size": 20,
                "field_offset": 0,
            }
            result = extract_text_data(temp_path, config)
            self.assertEqual(len(result), 0)
        finally:
            os.unlink(temp_path)


class TestQuestTableExtraction(unittest.TestCase):
    """Tests for quest table extraction (mhfinf.bin format)."""

    def _build_quest_binary(
        self, categories: list[list[list[str | None]]]
    ) -> bytes:
        """
        Build a binary with quest table structure.

        :param categories: List of categories. Each category is a list of quests.
            Each quest is a list of 8 strings (or None for empty slots).

        Layout:
        - 0x00-0x03: padding
        - 0x04-0x07: padding
        - 0x08-0x0B: padding
        - 0x0C-0x0F: padding
        - 0x10-0x13: pointer to important_nums → 0x18
        - 0x14-0x17: pointer to category table
        - 0x18-0x19: num_categories (u16)
        - 0x1A-0x1B: padding
        - category table, quest pointer arrays, QUEST_INFO_TBLs, text blocks, strings
        """
        num_categories = len(categories)

        # Phase 1: Calculate sizes
        header_size = 0x1C
        cat_table_start = header_size
        cat_table_size = num_categories * 8

        # Quest pointer arrays follow category table
        quest_arrays_start = cat_table_start + cat_table_size
        quest_arrays_size = sum(len(cat) for cat in categories) * 4

        # QUEST_INFO_TBL structs follow quest pointer arrays
        quest_struct_size = 0xBC  # 188 bytes
        quest_structs_start = quest_arrays_start + quest_arrays_size
        total_quests = sum(len(cat) for cat in categories)
        quest_structs_total = total_quests * quest_struct_size

        # Text blocks (8 pointers each) follow quest structs
        text_blocks_start = quest_structs_start + quest_structs_total
        text_blocks_total = total_quests * 8 * 4  # 8 pointers * 4 bytes

        # Strings follow text blocks
        strings_start = text_blocks_start + text_blocks_total

        # Phase 2: Encode strings and compute offsets
        all_encoded: list[bytes] = []
        string_offset_map: dict[int, int] = {}  # sequential index → file offset
        current = strings_start
        str_idx = 0
        for cat in categories:
            for quest_strings in cat:
                for s in quest_strings:
                    if s is not None:
                        enc = encode_game_string(s) + b"\x00"
                        string_offset_map[str_idx] = current
                        all_encoded.append(enc)
                        current += len(enc)
                    str_idx += 1

        # Phase 3: Build binary
        data = bytearray(strings_start)

        # Header
        struct.pack_into("<I", data, 0x10, 0x18)  # important_nums pointer
        struct.pack_into("<I", data, 0x14, cat_table_start)  # category table
        struct.pack_into("<H", data, 0x18, num_categories)

        # Build category table and quest data
        quest_array_offset = quest_arrays_start
        quest_struct_offset = quest_structs_start
        text_block_offset = text_blocks_start
        str_idx = 0

        for cat_idx, cat in enumerate(categories):
            # Category entry: endID, count, pointer to quest array
            cat_entry_addr = cat_table_start + cat_idx * 8
            end_id = (cat_idx + 1) * 100 - 1
            struct.pack_into("<H", data, cat_entry_addr, end_id)
            struct.pack_into("<H", data, cat_entry_addr + 2, len(cat))
            struct.pack_into("<I", data, cat_entry_addr + 4, quest_array_offset)

            for quest_idx, quest_strings in enumerate(cat):
                # Quest pointer array entry
                struct.pack_into("<I", data, quest_array_offset + quest_idx * 4,
                                 quest_struct_offset)

                # QUEST_INFO_TBL: put text pointer at +0x28
                struct.pack_into("<I", data, quest_struct_offset + 0x28,
                                 text_block_offset)

                # Text block: 8 string pointers
                for i, s in enumerate(quest_strings):
                    ptr = string_offset_map.get(str_idx, 0)
                    struct.pack_into("<I", data, text_block_offset + i * 4, ptr)
                    str_idx += 1

                quest_struct_offset += quest_struct_size
                text_block_offset += 8 * 4

            quest_array_offset += len(cat) * 4

        # Append strings
        for enc in all_encoded:
            data.extend(enc)

        return bytes(data)

    def test_single_quest(self):
        """Test extracting text from a single quest."""
        categories = [
            [["Title", "Main Obj", "Sub A", "Sub B",
              "Success", "Fail", "Hunter", "Description"]]
        ]
        binary = self._build_quest_binary(categories)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x14",
                "quest_table": True,
                "count_base_pointer": "0x10",
                "count_offset": "0x00",
                "count_type": "u16",
                "quest_text_offset": "0x28",
                "text_pointers_count": 8,
            }
            result = extract_text_data(temp_path, config)

            self.assertEqual(len(result), 1)
            self.assertIn("Title", result[0]["text"])
            self.assertIn("Main Obj", result[0]["text"])
            self.assertIn("Description", result[0]["text"])
            # All 8 strings joined
            self.assertEqual(result[0]["text"].count("<join"), 7)
        finally:
            os.unlink(temp_path)

    def test_multiple_categories(self):
        """Test extracting from multiple categories with multiple quests."""
        categories = [
            [
                ["Quest A1", "Obj A1", None, None, None, None, None, None],
                ["Quest A2", "Obj A2", None, None, None, None, None, None],
            ],
            [
                ["Quest B1", "Obj B1", None, None, None, None, "NPC", "Desc"],
            ],
        ]
        binary = self._build_quest_binary(categories)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x14",
                "quest_table": True,
                "count_base_pointer": "0x10",
                "count_offset": "0x00",
                "count_type": "u16",
                "quest_text_offset": "0x28",
                "text_pointers_count": 8,
            }
            result = extract_text_data(temp_path, config)

            self.assertEqual(len(result), 3)
            self.assertIn("Quest A1", result[0]["text"])
            self.assertIn("Quest A2", result[1]["text"])
            self.assertIn("Quest B1", result[2]["text"])
            self.assertIn("NPC", result[2]["text"])
        finally:
            os.unlink(temp_path)

    def test_empty_categories(self):
        """Test extraction with zero categories."""
        data = bytearray(0x20)
        struct.pack_into("<I", data, 0x10, 0x18)
        struct.pack_into("<I", data, 0x14, 0x1C)
        struct.pack_into("<H", data, 0x18, 0)  # 0 categories

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(bytes(data))
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x14",
                "quest_table": True,
                "count_base_pointer": "0x10",
                "count_offset": "0x00",
                "count_type": "u16",
            }
            result = extract_text_data(temp_path, config)
            self.assertEqual(len(result), 0)
        finally:
            os.unlink(temp_path)

    def test_quest_with_all_null_strings(self):
        """Test quest where all 8 text pointers are null."""
        categories = [
            [[None, None, None, None, None, None, None, None]]
        ]
        binary = self._build_quest_binary(categories)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x14",
                "quest_table": True,
                "count_base_pointer": "0x10",
                "count_offset": "0x00",
                "count_type": "u16",
                "quest_text_offset": "0x28",
                "text_pointers_count": 8,
            }
            result = extract_text_data(temp_path, config)
            # Quest with all-null strings should be skipped
            self.assertEqual(len(result), 0)
        finally:
            os.unlink(temp_path)


class TestNullTerminatedExtraction(unittest.TestCase):
    """Tests for null-terminated extraction via extract_text_data."""

    def _build_null_terminated_binary(
        self, groups: list[list[str]], pointers_per_entry: int = 1
    ) -> bytes:
        """
        Build a binary with null-terminated pointer groups.

        Layout:
        - 0x00-0x03: pointer to start of pointer array
        - 0x04+: pointer array (groups of pointers_per_entry),
                  terminated by a group whose first pointer is 0,
                  then actual strings
        """
        header_size = 4
        array_start = header_size

        # Calculate total pointer slots including terminator
        total_groups = len(groups)
        total_pointer_slots = total_groups * pointers_per_entry + pointers_per_entry  # +terminator
        strings_start = array_start + total_pointer_slots * 4

        # Encode strings and map offsets
        encoded_strings = []
        string_offsets: dict[int, int] = {}
        current = strings_start
        flat_idx = 0
        for group in groups:
            for s in group:
                if s is not None:
                    enc = encode_game_string(s) + b"\x00"
                    string_offsets[flat_idx] = current
                    encoded_strings.append(enc)
                    current += len(enc)
                flat_idx += 1

        data = bytearray(header_size)
        struct.pack_into("<I", data, 0x00, array_start)

        # Build pointer array
        flat_idx = 0
        for group in groups:
            for s in group:
                if s is not None:
                    data.extend(struct.pack("<I", string_offsets[flat_idx]))
                else:
                    data.extend(struct.pack("<I", 0))
                flat_idx += 1

        # Terminator: group of zeros
        for _ in range(pointers_per_entry):
            data.extend(struct.pack("<I", 0))

        # Strings
        for enc in encoded_strings:
            data.extend(enc)

        return bytes(data)

    def test_null_terminated_simple(self):
        """Test null-terminated extraction with single pointer per entry."""
        binary = self._build_null_terminated_binary(
            [["Hello"], ["World"], ["Test"]],
            pointers_per_entry=1
        )

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x00",
                "null_terminated": True,
                "pointers_per_entry": 1
            }
            result = extract_text_data(temp_path, config)

            self.assertEqual(len(result), 3)
            self.assertEqual(result[0]["text"], "Hello")
            self.assertEqual(result[1]["text"], "World")
            self.assertEqual(result[2]["text"], "Test")
        finally:
            os.unlink(temp_path)

    def test_null_terminated_s32px4(self):
        """Test null-terminated extraction with 4 pointers per entry (s32px4)."""
        groups = [
            ["Line1a", "Line1b", "Line1c", "Line1d"],
            ["Line2a", "Line2b", None, None],
        ]
        binary = self._build_null_terminated_binary(groups, pointers_per_entry=4)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x00",
                "null_terminated": True,
                "pointers_per_entry": 4
            }
            result = extract_text_data(temp_path, config)

            # Should have results with joined text (zero pointers in groups)
            self.assertGreater(len(result), 0)
            all_text = " ".join(r["text"] for r in result)
            self.assertIn("Line1a", all_text)
            self.assertIn("Line1d", all_text)
            self.assertIn("Line2a", all_text)
            self.assertIn("Line2b", all_text)
        finally:
            os.unlink(temp_path)

    def test_null_terminated_empty(self):
        """Test null-terminated extraction with immediate terminator."""
        # Just a header pointing to a zero (immediate terminator)
        data = bytearray(8)
        struct.pack_into("<I", data, 0x00, 0x04)  # pointer to offset 4
        struct.pack_into("<I", data, 0x04, 0)      # immediate zero = terminator

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(bytes(data))
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x00",
                "null_terminated": True,
                "pointers_per_entry": 1
            }
            result = extract_text_data(temp_path, config)
            self.assertEqual(len(result), 0)
        finally:
            os.unlink(temp_path)


class TestReadMultiPointerEntries(unittest.TestCase):
    """Tests for read_multi_pointer_entries function."""

    def _build_multi_pointer_binary(
        self, entries: list[list[str | None]], pointers_per_entry: int
    ) -> tuple[bytes, int]:
        """
        Build a binary with multi-pointer entries terminated by a null first pointer.

        Returns (data, start_position) where start_position is offset of the entry array.
        """
        start_position = 0
        total_entry_slots = len(entries) * pointers_per_entry
        terminator_slots = pointers_per_entry
        pointer_area_size = (total_entry_slots + terminator_slots) * 4
        strings_start = start_position + pointer_area_size

        encoded = []
        string_offsets: dict[int, int] = {}
        current = strings_start
        flat_idx = 0
        for entry in entries:
            for s in entry:
                if s is not None:
                    enc = encode_game_string(s) + b"\x00"
                    string_offsets[flat_idx] = current
                    encoded.append(enc)
                    current += len(enc)
                flat_idx += 1

        data = bytearray()
        flat_idx = 0
        for entry in entries:
            for s in entry:
                if s is not None:
                    data.extend(struct.pack("<I", string_offsets[flat_idx]))
                else:
                    data.extend(struct.pack("<I", 0))
                flat_idx += 1

        # Terminator
        for _ in range(pointers_per_entry):
            data.extend(struct.pack("<I", 0))

        for enc in encoded:
            data.extend(enc)

        return bytes(data), start_position

    def test_basic_multi_pointer(self):
        """Test basic multi-pointer entry reading."""
        entries = [
            ["Hello", "World"],
            ["Foo", "Bar"],
        ]
        data, start = self._build_multi_pointer_binary(entries, 2)
        bfile = BinaryFile.from_bytes(data)
        result = read_multi_pointer_entries(bfile, start, 2)

        self.assertEqual(len(result), 2)
        self.assertIn("Hello", result[0]["text"])
        self.assertIn("World", result[0]["text"])
        self.assertIn("<join", result[0]["text"])
        self.assertIn("Foo", result[1]["text"])
        self.assertIn("Bar", result[1]["text"])

    def test_null_internal_pointers(self):
        """Test that null internal pointers are skipped without breaking grouping."""
        entries = [
            ["A", None, "C"],
            ["D", "E", None],
        ]
        data, start = self._build_multi_pointer_binary(entries, 3)
        bfile = BinaryFile.from_bytes(data)
        result = read_multi_pointer_entries(bfile, start, 3)

        self.assertEqual(len(result), 2)
        # Entry 0: A and C joined
        self.assertIn("A", result[0]["text"])
        self.assertIn("C", result[0]["text"])
        # Entry 1: D and E joined
        self.assertIn("D", result[1]["text"])
        self.assertIn("E", result[1]["text"])

    def test_empty_array(self):
        """Test immediate terminator returns empty list."""
        # Just 3 zero pointers (terminator for pointers_per_entry=3)
        data = b"\x00" * 12
        bfile = BinaryFile.from_bytes(data)
        result = read_multi_pointer_entries(bfile, 0, 3)
        self.assertEqual(len(result), 0)

    def test_single_pointer_per_entry(self):
        """Test with 1 pointer per entry (degenerate case)."""
        entries = [["Hello"], ["World"]]
        data, start = self._build_multi_pointer_binary(entries, 1)
        bfile = BinaryFile.from_bytes(data)
        result = read_multi_pointer_entries(bfile, start, 1)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["text"], "Hello")
        self.assertEqual(result[1]["text"], "World")

    def test_grouping_correctness_vs_flat(self):
        """Test that grouped mode correctly separates entries that flat mode would merge.

        Given entries [ptr_a, ptr_b, ptr_c] and [ptr_d, 0, ptr_f]:
        - Flat mode would see [ptr_a, ptr_b, ptr_c, ptr_d, 0, ptr_f] and group
          as {ptr_a..ptr_d} and {ptr_f} (WRONG).
        - Grouped mode should produce {A, B, C} and {D, F} (CORRECT).
        """
        entries = [
            ["A", "B", "C"],
            ["D", None, "F"],
        ]
        data, start = self._build_multi_pointer_binary(entries, 3)
        bfile = BinaryFile.from_bytes(data)
        result = read_multi_pointer_entries(bfile, start, 3)

        self.assertEqual(len(result), 2)
        # First entry should have exactly A, B, C
        text0 = result[0]["text"]
        self.assertTrue(text0.startswith("A"))
        self.assertIn("B", text0)
        self.assertIn("C", text0)
        self.assertEqual(text0.count("<join"), 2)
        # Second entry should have D and F
        text1 = result[1]["text"]
        self.assertTrue(text1.startswith("D"))
        self.assertIn("F", text1)
        self.assertEqual(text1.count("<join"), 1)
        # D should NOT appear in first entry
        self.assertNotIn("D", text0)


class TestGroupedEntriesExtraction(unittest.TestCase):
    """Tests for grouped_entries null-terminated extraction via extract_text_data."""

    def _build_grouped_null_terminated_binary(
        self, entries: list[list[str | None]], pointers_per_entry: int
    ) -> bytes:
        """
        Build a binary with header pointer to grouped null-terminated entries.

        Layout:
        - 0x00-0x03: pointer to entry array (points to 0x04)
        - 0x04+: entry array, terminator, then strings
        """
        header_size = 4
        array_start = header_size
        total_entry_slots = len(entries) * pointers_per_entry
        terminator_slots = pointers_per_entry
        pointer_area_size = (total_entry_slots + terminator_slots) * 4
        strings_start = array_start + pointer_area_size

        encoded = []
        string_offsets: dict[int, int] = {}
        current = strings_start
        flat_idx = 0
        for entry in entries:
            for s in entry:
                if s is not None:
                    enc = encode_game_string(s) + b"\x00"
                    string_offsets[flat_idx] = current
                    encoded.append(enc)
                    current += len(enc)
                flat_idx += 1

        data = bytearray(header_size)
        struct.pack_into("<I", data, 0x00, array_start)

        flat_idx = 0
        for entry in entries:
            for s in entry:
                if s is not None:
                    data.extend(struct.pack("<I", string_offsets[flat_idx]))
                else:
                    data.extend(struct.pack("<I", 0))
                flat_idx += 1

        # Terminator
        for _ in range(pointers_per_entry):
            data.extend(struct.pack("<I", 0))

        for enc in encoded:
            data.extend(enc)

        return bytes(data)

    def test_grouped_entries_extraction(self):
        """Test grouped null-terminated extraction through extract_text_data."""
        entries = [
            ["Hello", "World", "Test"],
            ["Foo", None, "Baz"],
        ]
        binary = self._build_grouped_null_terminated_binary(entries, 3)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(binary)
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x00",
                "null_terminated": True,
                "grouped_entries": True,
                "pointers_per_entry": 3
            }
            result = extract_text_data(temp_path, config)

            self.assertEqual(len(result), 2)
            self.assertIn("Hello", result[0]["text"])
            self.assertIn("World", result[0]["text"])
            self.assertIn("Test", result[0]["text"])
            self.assertIn("Foo", result[1]["text"])
            self.assertIn("Baz", result[1]["text"])
        finally:
            os.unlink(temp_path)

    def test_grouped_entries_empty(self):
        """Test grouped extraction with immediate terminator."""
        # Header + 2 zero pointers (terminator for pointers_per_entry=2)
        data = bytearray(12)
        struct.pack_into("<I", data, 0x00, 0x04)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(bytes(data))
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x00",
                "null_terminated": True,
                "grouped_entries": True,
                "pointers_per_entry": 2
            }
            result = extract_text_data(temp_path, config)
            self.assertEqual(len(result), 0)
        finally:
            os.unlink(temp_path)

    def test_legacy_null_terminated_unchanged(self):
        """Test that existing null-terminated behavior (no grouped_entries) is unchanged."""
        # Build a simple null-terminated single-pointer array
        strings = ["Alpha", "Beta"]
        header_size = 4
        array_start = header_size
        strings_start = array_start + 3 * 4  # 2 entries + terminator

        encoded = []
        offsets = []
        current = strings_start
        for s in strings:
            enc = encode_game_string(s) + b"\x00"
            offsets.append(current)
            encoded.append(enc)
            current += len(enc)

        data = bytearray(header_size)
        struct.pack_into("<I", data, 0x00, array_start)
        for off in offsets:
            data.extend(struct.pack("<I", off))
        data.extend(struct.pack("<I", 0))  # terminator
        for enc in encoded:
            data.extend(enc)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(bytes(data))
            temp_path = f.name

        try:
            config = {
                "begin_pointer": "0x00",
                "null_terminated": True,
                "pointers_per_entry": 1
            }
            result = extract_text_data(temp_path, config)

            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["text"], "Alpha")
            self.assertEqual(result[1]["text"], "Beta")
        finally:
            os.unlink(temp_path)


class TestNewPacXpaths(unittest.TestCase):
    """Tests that new pac xpaths appear in headers.json."""

    def test_pac_text_tables_in_xpaths(self):
        """Test that all 22 new pac xpaths are discoverable."""
        result = get_all_xpaths(DEFAULT_HEADERS_PATH)

        # Null-terminated grouped tables (10)
        for suffix in ["14", "18", "1c", "20", "24", "28", "2c", "34", "50", "54"]:
            self.assertIn(f"pac/text_{suffix}", result)

        # Count-based strided tables (10)
        for suffix in ["40", "44", "60", "64", "68", "6c", "c8", "cc", "d0", "d4"]:
            self.assertIn(f"pac/text_{suffix}", result)

        # Two-field table (2)
        self.assertIn("pac/text_94/field_0", result)
        self.assertIn("pac/text_94/field_1", result)

    def test_grouped_entries_leaf_detection(self):
        """Test that grouped_entries configs are detected as leaves."""
        config = {
            "begin_pointer": "0x14",
            "null_terminated": True,
            "grouped_entries": True,
            "pointers_per_entry": 3
        }
        self.assertTrue(_is_extraction_leaf(config))

    def test_existing_pac_skills_unchanged(self):
        """Test that existing pac/skills xpaths still work."""
        result = get_all_xpaths(DEFAULT_HEADERS_PATH)
        self.assertIn("pac/skills/name", result)
        self.assertIn("pac/skills/effect", result)
        self.assertIn("pac/skills/effect_z", result)
        self.assertIn("pac/skills/description", result)


class TestParseJoinedText(unittest.TestCase):
    """Tests for parse_joined_text function."""

    def test_no_joins(self):
        """Test text without join tags returns single pair."""
        from src.import_data import parse_joined_text
        result = parse_joined_text(100, "Hello World")
        self.assertEqual(result, [(100, "Hello World")])

    def test_single_join(self):
        """Test text with one join tag."""
        from src.import_data import parse_joined_text
        result = parse_joined_text(100, 'Part1<join at="104">Part2')
        self.assertEqual(result, [(100, "Part1"), (104, "Part2")])

    def test_multiple_joins(self):
        """Test text with multiple join tags."""
        from src.import_data import parse_joined_text
        result = parse_joined_text(100, 'A<join at="104">B<join at="108">C')
        self.assertEqual(result, [(100, "A"), (104, "B"), (108, "C")])

    def test_empty_string(self):
        """Test empty string."""
        from src.import_data import parse_joined_text
        result = parse_joined_text(100, "")
        self.assertEqual(result, [(100, "")])

    def test_empty_parts_in_join(self):
        """Test join where first part is empty."""
        from src.import_data import parse_joined_text
        result = parse_joined_text(100, '<join at="104">Only')
        self.assertEqual(result, [(100, ""), (104, "Only")])


class TestRebuildSection(unittest.TestCase):
    """Tests for rebuild_section and in-place translation insertion."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)

    def _create_pointer_pair_binary(self, strings: list[str]) -> tuple[bytes, dict]:
        """
        Create a binary with pointer-pair layout matching headers.json format.

        Layout:
        - 0x00-0x03: pointer to start of pointer table (begin_pointer dereference)
        - 0x04-0x07: pointer to end of pointer table (next_field_pointer dereference)
        - 0x08+: pointer table, then strings

        Returns (binary_data, config).
        """
        header_size = 8
        pointer_table_start = header_size
        pointer_table_size = len(strings) * 4
        strings_start = pointer_table_start + pointer_table_size

        encoded = []
        string_offsets = []
        current = strings_start
        for s in strings:
            enc = encode_game_string(s) + b"\x00"
            string_offsets.append(current)
            encoded.append(enc)
            current += len(enc)

        data = bytearray(header_size)
        # begin_pointer at 0x00 → points to pointer_table_start
        struct.pack_into("<I", data, 0x00, pointer_table_start)
        # next_field_pointer at 0x04 → points to end of pointer table
        struct.pack_into("<I", data, 0x04, pointer_table_start + pointer_table_size)

        # Pointer table
        for offset in string_offsets:
            data.extend(struct.pack("<I", offset))
        # Strings
        for enc in encoded:
            data.extend(enc)

        config = {
            "begin_pointer": "0x00",
            "next_field_pointer": "0x04",
        }
        return bytes(data), config

    def test_rebuild_with_translation(self):
        """Test rebuild replaces translated strings and keeps originals."""
        from src.import_data import rebuild_section

        binary_data, config = self._create_pointer_pair_binary(
            ["Hello", "World", "Test"]
        )
        # Pointer table starts at 0x08, so pointers are at 0x08, 0x0C, 0x10
        # Translate only the first string (pointer at 0x08)
        new_strings = [(0x08, "Bonjour")]
        output_path = os.path.join(self.temp_dir, "rebuilt.bin")

        rebuild_section(binary_data, config, new_strings, output_path)

        with open(output_path, "rb") as f:
            result = f.read()

        # All 3 pointers should now point into the appended block
        original_size = len(binary_data)
        for ptr_offset in (0x08, 0x0C, 0x10):
            ptr = struct.unpack("<I", result[ptr_offset:ptr_offset + 4])[0]
            self.assertGreaterEqual(ptr, original_size,
                                    f"Pointer at 0x{ptr_offset:x} should point to appended block")

        # Verify string content
        ptr0 = struct.unpack("<I", result[0x08:0x0C])[0]
        end0 = result.index(b"\x00", ptr0)
        self.assertEqual(result[ptr0:end0], encode_game_string("Bonjour"))

        ptr1 = struct.unpack("<I", result[0x0C:0x10])[0]
        end1 = result.index(b"\x00", ptr1)
        self.assertEqual(result[ptr1:end1], encode_game_string("World"))

        ptr2 = struct.unpack("<I", result[0x10:0x14])[0]
        end2 = result.index(b"\x00", ptr2)
        self.assertEqual(result[ptr2:end2], encode_game_string("Test"))

    def test_rebuild_all_translated(self):
        """Test rebuild when all strings are translated."""
        from src.import_data import rebuild_section

        binary_data, config = self._create_pointer_pair_binary(["A", "B"])
        new_strings = [(0x08, "X"), (0x0C, "Y")]
        output_path = os.path.join(self.temp_dir, "rebuilt.bin")

        rebuild_section(binary_data, config, new_strings, output_path)

        with open(output_path, "rb") as f:
            result = f.read()

        ptr0 = struct.unpack("<I", result[0x08:0x0C])[0]
        end0 = result.index(b"\x00", ptr0)
        self.assertEqual(result[ptr0:end0], encode_game_string("X"))

        ptr1 = struct.unpack("<I", result[0x0C:0x10])[0]
        end1 = result.index(b"\x00", ptr1)
        self.assertEqual(result[ptr1:end1], encode_game_string("Y"))

    def test_rebuild_with_joined_entries(self):
        """Test rebuild with join tags in both original and translation."""
        from src.import_data import rebuild_section

        # Build binary with join pattern: [ptr1, ptr2, 0, ptr3]
        # This creates 2 entries: first has join, second is standalone
        header_size = 8
        pointer_table_start = header_size
        # 4 pointer slots (ptr, ptr, 0-separator, ptr)
        pointer_table_size = 4 * 4
        strings_start = pointer_table_start + pointer_table_size

        s1 = encode_game_string("Part1") + b"\x00"
        s2 = encode_game_string("Part2") + b"\x00"
        s3 = encode_game_string("Standalone") + b"\x00"

        data = bytearray(header_size)
        struct.pack_into("<I", data, 0x00, pointer_table_start)
        struct.pack_into("<I", data, 0x04, pointer_table_start + pointer_table_size)

        # Pointer table: [ptr_to_s1, ptr_to_s2, 0, ptr_to_s3]
        data.extend(struct.pack("<I", strings_start))
        data.extend(struct.pack("<I", strings_start + len(s1)))
        data.extend(struct.pack("<I", 0))  # separator
        data.extend(struct.pack("<I", strings_start + len(s1) + len(s2)))
        data.extend(s1 + s2 + s3)

        binary_data = bytes(data)
        config = {
            "begin_pointer": "0x00",
            "next_field_pointer": "0x04",
        }

        # Translate the joined entry (pointer at 0x08 = first ptr in table)
        # The extracted text would be: 'Part1<join at="12">Part2'
        # where 12 = 0x0C = second pointer offset
        new_strings = [(0x08, f'Trad1<join at="12">Trad2')]
        output_path = os.path.join(self.temp_dir, "rebuilt.bin")

        rebuild_section(binary_data, config, new_strings, output_path)

        with open(output_path, "rb") as f:
            result = f.read()

        # Pointer at 0x08 should point to "Trad1"
        ptr0 = struct.unpack("<I", result[0x08:0x0C])[0]
        end0 = result.index(b"\x00", ptr0)
        self.assertEqual(result[ptr0:end0], encode_game_string("Trad1"))

        # Pointer at 0x0C should point to "Trad2"
        ptr1 = struct.unpack("<I", result[0x0C:0x10])[0]
        end1 = result.index(b"\x00", ptr1)
        self.assertEqual(result[ptr1:end1], encode_game_string("Trad2"))

        # Pointer at 0x14 (standalone) should keep "Standalone"
        ptr2 = struct.unpack("<I", result[0x14:0x18])[0]
        end2 = result.index(b"\x00", ptr2)
        self.assertEqual(result[ptr2:end2], encode_game_string("Standalone"))

    def test_backward_compat_no_xpath(self):
        """Test that import_from_csv without xpath still uses append strategy."""
        from src.import_data import import_from_csv

        strings = ["Hello", "World", "Test"]
        # Simple pointer table binary (no header indirection)
        pointer_table_size = len(strings) * 4
        string_offsets = []
        current_offset = pointer_table_size
        encoded_strings = []
        for s in strings:
            encoded = encode_game_string(s) + b"\x00"
            string_offsets.append(current_offset)
            encoded_strings.append(encoded)
            current_offset += len(encoded)

        binary_data = b""
        for offset in string_offsets:
            binary_data += struct.pack("<I", offset)
        for encoded in encoded_strings:
            binary_data += encoded

        binary_path = os.path.join(self.temp_dir, "test.bin")
        with open(binary_path, "wb") as f:
            f.write(binary_data)

        csv_path = os.path.join(self.temp_dir, "translations.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            writer.writerow(["0x0@test.bin", "Hello", "Bonjour"])

        output_path = os.path.join(self.temp_dir, "output.bin")
        result = import_from_csv(csv_path, binary_path, output_path=output_path)

        self.assertIsNotNone(result)
        with open(output_path, "rb") as f:
            output_data = f.read()

        # Append strategy: only translated pointer changes, others keep original
        pointer_0 = struct.unpack("<I", output_data[0:4])[0]
        self.assertGreaterEqual(pointer_0, len(binary_data))
        end = output_data.index(b"\x00", pointer_0)
        self.assertEqual(output_data[pointer_0:end], encode_game_string("Bonjour"))

        # Untranslated pointers should still point to original locations
        pointer_1 = struct.unpack("<I", output_data[4:8])[0]
        self.assertEqual(pointer_1, string_offsets[1])

    def test_import_with_xpath_uses_rebuild(self):
        """Test that import_from_csv with xpath uses rebuild_section."""
        from src.import_data import import_from_csv

        binary_data, config = self._create_pointer_pair_binary(
            ["Hello", "World", "Test"]
        )
        binary_path = os.path.join(self.temp_dir, "test.bin")
        with open(binary_path, "wb") as f:
            f.write(binary_data)

        # Create a matching headers.json
        headers_path = os.path.join(self.temp_dir, "headers.json")
        headers = {"test": {"section": config}}
        with open(headers_path, "w") as f:
            json.dump(headers, f)

        csv_path = os.path.join(self.temp_dir, "translations.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            writer.writerow(["0x8@test.bin", "Hello", "Bonjour"])

        output_path = os.path.join(self.temp_dir, "output.bin")
        result = import_from_csv(
            csv_path, binary_path, output_path=output_path,
            xpath="test/section", headers_path=headers_path
        )

        self.assertIsNotNone(result)
        with open(output_path, "rb") as f:
            output_data = f.read()

        # Rebuild strategy: ALL pointers updated to appended block
        original_size = len(binary_data)
        for ptr_offset in (0x08, 0x0C, 0x10):
            ptr = struct.unpack("<I", output_data[ptr_offset:ptr_offset + 4])[0]
            self.assertGreaterEqual(ptr, original_size)

        # Verify translated string
        ptr0 = struct.unpack("<I", output_data[0x08:0x0C])[0]
        end0 = output_data.index(b"\x00", ptr0)
        self.assertEqual(output_data[ptr0:end0], encode_game_string("Bonjour"))

        # Verify untranslated strings preserved
        ptr1 = struct.unpack("<I", output_data[0x0C:0x10])[0]
        end1 = output_data.index(b"\x00", ptr1)
        self.assertEqual(output_data[ptr1:end1], encode_game_string("World"))


class TestExtractTextDataFromBytes(unittest.TestCase):
    """Tests for extract_text_data_from_bytes function."""

    def test_from_bytes_matches_from_file(self):
        """Test that extract_text_data_from_bytes gives same result as extract_text_data."""
        from src.common import extract_text_data_from_bytes

        strings = ["Alpha", "Beta", "Gamma"]
        header_size = 8
        pointer_table_start = header_size
        pointer_table_size = len(strings) * 4
        strings_start = pointer_table_start + pointer_table_size

        encoded = []
        string_offsets = []
        current = strings_start
        for s in strings:
            enc = encode_game_string(s) + b"\x00"
            string_offsets.append(current)
            encoded.append(enc)
            current += len(enc)

        data = bytearray(header_size)
        struct.pack_into("<I", data, 0x00, pointer_table_start)
        struct.pack_into("<I", data, 0x04, pointer_table_start + pointer_table_size)
        for offset in string_offsets:
            data.extend(struct.pack("<I", offset))
        for enc in encoded:
            data.extend(enc)

        binary_data = bytes(data)
        config = {
            "begin_pointer": "0x00",
            "next_field_pointer": "0x04",
        }

        # Test from_bytes
        result_bytes = extract_text_data_from_bytes(binary_data, config)

        # Test from file
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(binary_data)
            temp_path = f.name

        try:
            result_file = extract_text_data(temp_path, config)
            self.assertEqual(result_bytes, result_file)
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    unittest.main()
