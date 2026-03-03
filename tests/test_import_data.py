"""Tests for src/import_data.py — import and rebuild functions."""

import csv
import json
import os
import struct
import tempfile
import unittest

from src.common import GAME_ENCODING
from src.binary_file import BinaryFile
from src.import_data import (
    append_to_binary,
    parse_location,
    parse_joined_text,
    get_new_strings,
    get_new_strings_from_json,
    get_new_strings_auto,
    import_from_csv,
    CSVParseError,
)


class TestAppendToBinary(unittest.TestCase):
    """Test append_to_binary function."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmpdir))

    def test_basic_append(self):
        # Build a simple binary with one pointer and one string
        string = "Original".encode(GAME_ENCODING) + b"\x00"
        ptr_offset = 0
        string_offset = 4
        data = struct.pack("<I", string_offset) + string

        bin_path = os.path.join(self.tmpdir, "test.bin")
        with open(bin_path, "wb") as f:
            f.write(data)

        # Append a new string
        new_strings = [(ptr_offset, "New")]
        append_to_binary(new_strings, (ptr_offset,), bin_path)

        # Verify the pointer was updated
        with open(bin_path, "rb") as f:
            result = f.read()

        new_ptr = struct.unpack_from("<I", result, ptr_offset)[0]
        # New pointer should point to the appended string at end of original data
        self.assertGreater(new_ptr, string_offset)
        # Verify the appended string is there
        bfile = BinaryFile.from_bytes(result)
        bfile.seek(new_ptr)
        raw = bytearray()
        b = bfile.read(1)
        while b != b"\x00" and b != b"":
            raw.extend(b)
            b = bfile.read(1)
        self.assertEqual(raw.decode(GAME_ENCODING), "New")

    def test_multiple_appends(self):
        # Two pointers, two strings
        str_a = "AAA".encode(GAME_ENCODING) + b"\x00"
        str_b = "BBB".encode(GAME_ENCODING) + b"\x00"
        strings_start = 8
        data = bytearray()
        data.extend(struct.pack("<I", strings_start))
        data.extend(struct.pack("<I", strings_start + len(str_a)))
        data.extend(str_a)
        data.extend(str_b)

        bin_path = os.path.join(self.tmpdir, "test.bin")
        with open(bin_path, "wb") as f:
            f.write(bytes(data))

        new_strings = [(0, "XXX"), (4, "YYY")]
        append_to_binary(new_strings, (0, 4), bin_path)

        with open(bin_path, "rb") as f:
            result = f.read()

        # Both pointers should have been updated
        ptr_a = struct.unpack_from("<I", result, 0)[0]
        ptr_b = struct.unpack_from("<I", result, 4)[0]
        self.assertGreater(ptr_a, strings_start)
        self.assertGreater(ptr_b, strings_start)
        self.assertNotEqual(ptr_a, ptr_b)


class TestParseLocation(unittest.TestCase):
    """Test parse_location."""

    def test_basic(self):
        self.assertEqual(parse_location("0x100@test.bin"), 0x100)

    def test_no_at_raises(self):
        with self.assertRaises(CSVParseError):
            parse_location("0x100")

    def test_invalid_hex_raises(self):
        with self.assertRaises(CSVParseError):
            parse_location("xyz@test.bin")


class TestParseJoinedText(unittest.TestCase):
    """Test parse_joined_text."""

    def test_no_joins(self):
        result = parse_joined_text(100, "simple text")
        self.assertEqual(result, [(100, "simple text")])

    def test_with_joins(self):
        result = parse_joined_text(10, 'first<join at="20">second<join at="30">third')
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0], (10, "first"))
        self.assertEqual(result[1], (20, "second"))
        self.assertEqual(result[2], (30, "third"))


class TestGetNewStringsFromJson(unittest.TestCase):
    """Test get_new_strings_from_json."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmpdir))

    def test_basic(self):
        data = {
            "strings": [
                {"location": "0x10@test.bin", "source": "old", "target": "new"},
                {"location": "0x20@test.bin", "source": "same", "target": "same"},
            ]
        }
        path = os.path.join(self.tmpdir, "test.json")
        with open(path, "w") as f:
            json.dump(data, f)

        result = get_new_strings_from_json(path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], (0x10, "new"))

    def test_invalid_json_raises(self):
        path = os.path.join(self.tmpdir, "bad.json")
        with open(path, "w") as f:
            f.write("not json")
        with self.assertRaises(CSVParseError):
            get_new_strings_from_json(path)

    def test_missing_strings_key_raises(self):
        path = os.path.join(self.tmpdir, "no_strings.json")
        with open(path, "w") as f:
            json.dump({"data": []}, f)
        with self.assertRaises(CSVParseError):
            get_new_strings_from_json(path)


class TestGetNewStringsAuto(unittest.TestCase):
    """Test get_new_strings_auto format detection."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmpdir))

    def test_detects_json(self):
        path = os.path.join(self.tmpdir, "test.json")
        with open(path, "w") as f:
            json.dump({"strings": []}, f)
        result = get_new_strings_auto(path)
        self.assertEqual(result, [])

    def test_detects_csv(self):
        path = os.path.join(self.tmpdir, "test.csv")
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
        result = get_new_strings_auto(path)
        self.assertEqual(result, [])


class TestImportFromCsvXpathValidation(unittest.TestCase):
    """Test that import_from_csv validates xpath early."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmpdir))

    def test_invalid_xpath_raises_clear_error(self):
        csv_path = os.path.join(self.tmpdir, "test.csv")
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            writer.writerow(["0x10@test.bin", "old", "new"])

        bin_path = os.path.join(self.tmpdir, "test.bin")
        with open(bin_path, "wb") as f:
            f.write(b"\x00" * 64)

        headers_path = os.path.join(self.tmpdir, "headers.json")
        with open(headers_path, "w") as f:
            json.dump({
                "dat": {
                    "items": {
                        "begin_pointer": "0x0",
                        "next_field_pointer": "0x4",
                    }
                }
            }, f)

        with self.assertRaises(ValueError) as ctx:
            import_from_csv(
                csv_path, bin_path,
                xpath="dat/nonexistent",
                headers_path=headers_path,
            )
        self.assertIn("not found", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
