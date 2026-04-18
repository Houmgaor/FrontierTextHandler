"""Tests for src/export.py — export and batch extraction functions."""

import json
import os
import struct
import tempfile
import unittest

from src.common import GAME_ENCODING, DEFAULT_HEADERS_PATH
from src.export import (
    extract_from_file,
    extract_all,
    _batch_extract,
)


class TestExtractFromFile(unittest.TestCase):
    """Test extract_from_file with synthetic binary data."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmpdir))

    def _build_standard_binary(self, strings: list[str]) -> bytes:
        """Build a binary with standard pointer-pair layout."""
        header_size = 8
        num_strs = len(strings)
        table_size = num_strs * 4
        table_start = header_size
        strings_start = header_size + table_size

        encoded = []
        offsets = []
        current = strings_start
        for s in strings:
            offsets.append(current)
            enc = s.encode(GAME_ENCODING) + b"\x00"
            encoded.append(enc)
            current += len(enc)

        data = bytearray()
        data.extend(struct.pack("<I", table_start))
        data.extend(struct.pack("<I", table_start + table_size))
        for off in offsets:
            data.extend(struct.pack("<I", off))
        for enc in encoded:
            data.extend(enc)
        return bytes(data)

    def _write_headers(self, config: dict) -> str:
        path = os.path.join(self.tmpdir, "headers.json")
        with open(path, "w") as f:
            json.dump(config, f)
        return path

    def test_basic_extraction(self):
        data = self._build_standard_binary(["Hello", "World"])
        bin_path = os.path.join(self.tmpdir, "test.bin")
        with open(bin_path, "wb") as f:
            f.write(data)

        headers_path = self._write_headers({
            "test": {
                "items": {
                    "begin_pointer": "0x0",
                    "next_field_pointer": "0x4",
                }
            }
        })

        output_dir = os.path.join(self.tmpdir, "out")
        # ReFrontier TSV is opt-in since 1.7.0; pass refrontier_tsv=True
        # to keep coverage that the legacy path still works.
        csv_path, ref_path, json_path = extract_from_file(
            bin_path, "test/items", "", output_dir, headers_path,
            refrontier_tsv=True,
        )

        self.assertTrue(os.path.exists(csv_path))
        self.assertTrue(os.path.exists(ref_path))
        self.assertTrue(os.path.exists(json_path))

    def test_refrontier_tsv_off_by_default(self):
        data = self._build_standard_binary(["Foo", "Bar"])
        bin_path = os.path.join(self.tmpdir, "test.bin")
        with open(bin_path, "wb") as f:
            f.write(data)

        headers_path = self._write_headers({
            "test": {
                "items": {
                    "begin_pointer": "0x0",
                    "next_field_pointer": "0x4",
                }
            }
        })

        output_dir = os.path.join(self.tmpdir, "out_default")
        csv_path, ref_path, json_path = extract_from_file(
            bin_path, "test/items", "", output_dir, headers_path
        )

        self.assertTrue(os.path.exists(csv_path))
        self.assertTrue(os.path.exists(json_path))
        self.assertEqual(ref_path, "")
        self.assertFalse(
            os.path.exists(os.path.join(output_dir, "refrontier.csv"))
        )

    def test_no_data_raises(self):
        # Binary with pointer table pointing to nothing
        data = struct.pack("<II", 8, 8)  # start == end → 0 length
        bin_path = os.path.join(self.tmpdir, "empty.bin")
        with open(bin_path, "wb") as f:
            f.write(data)

        headers_path = self._write_headers({
            "test": {
                "items": {
                    "begin_pointer": "0x0",
                    "next_field_pointer": "0x4",
                }
            }
        })

        output_dir = os.path.join(self.tmpdir, "out")
        with self.assertRaises(ValueError):
            extract_from_file(bin_path, "test/items", "", output_dir, headers_path)


class TestExtractAll(unittest.TestCase):
    """Test extract_all batch function."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmpdir))

    def _build_standard_binary(self, strings: list[str]) -> bytes:
        header_size = 8
        num_strs = len(strings)
        table_size = num_strs * 4
        table_start = header_size
        strings_start = header_size + table_size

        encoded = []
        offsets = []
        current = strings_start
        for s in strings:
            offsets.append(current)
            enc = s.encode(GAME_ENCODING) + b"\x00"
            encoded.append(enc)
            current += len(enc)

        data = bytearray()
        data.extend(struct.pack("<I", table_start))
        data.extend(struct.pack("<I", table_start + table_size))
        for off in offsets:
            data.extend(struct.pack("<I", off))
        for enc in encoded:
            data.extend(enc)
        return bytes(data)

    def test_extract_all_basic(self):
        data = self._build_standard_binary(["Alpha", "Beta"])
        bin_path = os.path.join(self.tmpdir, "mhfdat.bin")
        with open(bin_path, "wb") as f:
            f.write(data)

        headers_path = os.path.join(self.tmpdir, "headers.json")
        with open(headers_path, "w") as f:
            json.dump({
                "dat": {
                    "test": {
                        "begin_pointer": "0x0",
                        "next_field_pointer": "0x4",
                    }
                }
            }, f)

        output_dir = os.path.join(self.tmpdir, "out")
        generated = extract_all(
            {"dat": bin_path}, output_dir, headers_path
        )

        self.assertEqual(len(generated), 1)
        self.assertTrue(os.path.exists(generated[0]))

    def test_extract_all_missing_file_skips(self):
        headers_path = os.path.join(self.tmpdir, "headers.json")
        with open(headers_path, "w") as f:
            json.dump({
                "dat": {
                    "test": {
                        "begin_pointer": "0x0",
                        "next_field_pointer": "0x4",
                    }
                }
            }, f)

        output_dir = os.path.join(self.tmpdir, "out")
        generated = extract_all(
            {"dat": "/nonexistent/path.bin"}, output_dir, headers_path
        )
        self.assertEqual(len(generated), 0)


class TestBatchExtract(unittest.TestCase):
    """Test _batch_extract helper."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmpdir))

    def test_missing_dir_raises(self):
        with self.assertRaises(FileNotFoundError):
            _batch_extract(
                "/nonexistent/dir", self.tmpdir, "test", "test",
                lambda fp: []
            )

    def test_empty_dir_returns_empty(self):
        input_dir = os.path.join(self.tmpdir, "input")
        os.makedirs(input_dir)
        result = _batch_extract(
            input_dir, os.path.join(self.tmpdir, "out"), "test", "test",
            lambda fp: []
        )
        self.assertEqual(result, [])

    def test_non_bin_files_skipped(self):
        input_dir = os.path.join(self.tmpdir, "input")
        os.makedirs(input_dir)
        with open(os.path.join(input_dir, "readme.txt"), "w") as f:
            f.write("not a bin")

        result = _batch_extract(
            input_dir, os.path.join(self.tmpdir, "out"), "test", "test",
            lambda fp: [{"offset": 0, "text": "test"}]
        )
        self.assertEqual(result, [])

    def test_extraction_error_skips(self):
        input_dir = os.path.join(self.tmpdir, "input")
        os.makedirs(input_dir)
        with open(os.path.join(input_dir, "bad.bin"), "wb") as f:
            f.write(b"\x00")

        def _raise(fp):
            raise ValueError("bad file")

        result = _batch_extract(
            input_dir, os.path.join(self.tmpdir, "out"), "test", "test",
            _raise
        )
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
