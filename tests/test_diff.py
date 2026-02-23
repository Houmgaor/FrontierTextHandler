"""
Tests for the diff module.

Tests string comparison between CSV files, binary files, JSON files, and mixed formats.
"""
import csv
import json
import os
import struct
import tempfile
import unittest

from src import (
    DiffResult,
    diff_strings,
    load_strings,
    load_strings_from_json,
    format_diff,
    encode_game_string,
)
from src.common import FTXT_MAGIC, FTXT_HEADER_SIZE
from src.diff import (
    load_strings_from_csv,
    load_strings_from_binary,
    _location_key,
)


def _write_csv(path: str, rows: list[list[str]]) -> None:
    """Write a CSV file with header + rows."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["location", "source", "target"])
        for row in rows:
            writer.writerow(row)


def _write_json(path: str, entries: list[dict]) -> None:
    """Write a JSON file with metadata + strings array."""
    data = {
        "metadata": {"source_file": "test.bin", "version": "1.0.0"},
        "strings": entries,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _build_ftxt(strings: list[str]) -> bytes:
    """Build a synthetic FTXT binary for testing."""
    encoded_parts = []
    for s in strings:
        encoded_parts.append(encode_game_string(s) + b"\x00")
    text_block = b"".join(encoded_parts)

    header = bytearray(FTXT_HEADER_SIZE)
    struct.pack_into("<I", header, 0x00, FTXT_MAGIC)
    struct.pack_into("<H", header, 0x0A, len(strings))
    struct.pack_into("<I", header, 0x0C, len(text_block))

    return bytes(header) + text_block


class TestLocationKey(unittest.TestCase):
    """Tests for _location_key helper."""

    def test_strips_filename(self):
        self.assertEqual(_location_key("0x1234@mhfdat.bin"), "0x1234")

    def test_no_filename(self):
        self.assertEqual(_location_key("0x1234"), "0x1234")

    def test_complex_path(self):
        self.assertEqual(_location_key("0xabcdef@data/path/file.bin"), "0xabcdef")


class TestDiffStrings(unittest.TestCase):
    """Tests for diff_strings core logic."""

    def test_identical_dicts(self):
        strings = {"0x0": "Hello", "0x4": "World"}
        result = diff_strings(strings, strings.copy(), "a", "b")
        self.assertEqual(len(result.modified), 0)
        self.assertEqual(len(result.added), 0)
        self.assertEqual(len(result.removed), 0)
        self.assertEqual(result.unchanged, 2)

    def test_modified_strings(self):
        a = {"0x0": "Hello", "0x4": "World"}
        b = {"0x0": "Bonjour", "0x4": "Monde"}
        result = diff_strings(a, b, "a", "b")
        self.assertEqual(len(result.modified), 2)
        self.assertEqual(result.modified[0], ("0x0", "Hello", "Bonjour"))
        self.assertEqual(result.modified[1], ("0x4", "World", "Monde"))
        self.assertEqual(result.unchanged, 0)

    def test_added_strings(self):
        a = {"0x0": "Hello"}
        b = {"0x0": "Hello", "0x4": "New"}
        result = diff_strings(a, b, "a", "b")
        self.assertEqual(len(result.added), 1)
        self.assertEqual(result.added[0], ("0x4", "New"))
        self.assertEqual(result.unchanged, 1)

    def test_removed_strings(self):
        a = {"0x0": "Hello", "0x4": "Old"}
        b = {"0x0": "Hello"}
        result = diff_strings(a, b, "a", "b")
        self.assertEqual(len(result.removed), 1)
        self.assertEqual(result.removed[0], ("0x4", "Old"))
        self.assertEqual(result.unchanged, 1)

    def test_mixed_changes(self):
        a = {"0x0": "Same", "0x4": "Changed", "0x8": "Removed"}
        b = {"0x0": "Same", "0x4": "Modified", "0xc": "Added"}
        result = diff_strings(a, b, "a", "b")
        self.assertEqual(len(result.modified), 1)
        self.assertEqual(len(result.added), 1)
        self.assertEqual(len(result.removed), 1)
        self.assertEqual(result.unchanged, 1)

    def test_empty_dicts(self):
        result = diff_strings({}, {}, "a", "b")
        self.assertEqual(len(result.modified), 0)
        self.assertEqual(len(result.added), 0)
        self.assertEqual(len(result.removed), 0)
        self.assertEqual(result.unchanged, 0)

    def test_a_empty_b_has_strings(self):
        b = {"0x0": "New"}
        result = diff_strings({}, b, "a", "b")
        self.assertEqual(len(result.added), 1)
        self.assertEqual(result.unchanged, 0)

    def test_a_has_strings_b_empty(self):
        a = {"0x0": "Old"}
        result = diff_strings(a, {}, "a", "b")
        self.assertEqual(len(result.removed), 1)
        self.assertEqual(result.unchanged, 0)


class TestFormatDiff(unittest.TestCase):
    """Tests for format_diff output."""

    def test_no_differences(self):
        result = DiffResult(file_a="a.csv", file_b="b.csv", unchanged=5)
        output = format_diff(result)
        self.assertIn("No differences found", output)
        self.assertIn("5 strings", output)
        self.assertIn("0 modified", output)

    def test_with_modifications(self):
        result = DiffResult(
            file_a="a.csv",
            file_b="b.csv",
            modified=[("0x0", "Old", "New")],
            unchanged=2,
        )
        output = format_diff(result)
        self.assertIn("Modified (1)", output)
        self.assertIn('"Old" -> "New"', output)
        self.assertIn("3 strings", output)

    def test_with_all_change_types(self):
        result = DiffResult(
            file_a="a.csv",
            file_b="b.csv",
            modified=[("0x0", "A", "B")],
            added=[("0x4", "New")],
            removed=[("0x8", "Gone")],
            unchanged=1,
        )
        output = format_diff(result)
        self.assertIn("Modified (1)", output)
        self.assertIn("Added (1)", output)
        self.assertIn("Removed (1)", output)
        self.assertIn("1 modified, 1 added, 1 removed, 1 unchanged", output)


class TestLoadStringsFromCSV(unittest.TestCase):
    """Tests for CSV string loading."""

    def test_basic_csv(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline="", encoding="utf-8"
        ) as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            writer.writerow(["0x100@mhfdat.bin", "Hello", "Bonjour"])
            writer.writerow(["0x104@mhfdat.bin", "World", "Monde"])
            path = f.name

        try:
            strings = load_strings_from_csv(path)
            self.assertEqual(strings["0x100"], "Bonjour")
            self.assertEqual(strings["0x104"], "Monde")
            self.assertEqual(len(strings), 2)
        finally:
            os.unlink(path)

    def test_empty_csv(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline="", encoding="utf-8"
        ) as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            path = f.name

        try:
            strings = load_strings_from_csv(path)
            self.assertEqual(len(strings), 0)
        finally:
            os.unlink(path)


class TestLoadStringsFromJSON(unittest.TestCase):
    """Tests for JSON string loading."""

    def test_basic_json(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            _write_json(f.name, [
                {"location": "0x100@mhfdat.bin", "source": "Hello", "target": "Bonjour"},
                {"location": "0x104@mhfdat.bin", "source": "World", "target": "Monde"},
            ])
            path = f.name

        try:
            strings = load_strings_from_json(path)
            self.assertEqual(strings["0x100"], "Bonjour")
            self.assertEqual(strings["0x104"], "Monde")
            self.assertEqual(len(strings), 2)
        finally:
            os.unlink(path)

    def test_empty_json(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            _write_json(f.name, [])
            path = f.name

        try:
            strings = load_strings_from_json(path)
            self.assertEqual(len(strings), 0)
        finally:
            os.unlink(path)

    def test_skips_invalid_entries(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            data = {
                "metadata": {},
                "strings": [
                    {"location": "0x100@test.bin", "source": "A", "target": "B"},
                    "not a dict",
                    {"location": "0x104@test.bin", "source": "C"},  # missing target
                    {"target": "D"},  # missing location
                ],
            }
            json.dump(data, f)
            path = f.name

        try:
            strings = load_strings_from_json(path)
            self.assertEqual(len(strings), 1)
            self.assertEqual(strings["0x100"], "B")
        finally:
            os.unlink(path)

    def test_no_strings_key(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump({"metadata": {}}, f)
            path = f.name

        try:
            strings = load_strings_from_json(path)
            self.assertEqual(len(strings), 0)
        finally:
            os.unlink(path)


class TestLoadStringsFromBinary(unittest.TestCase):
    """Tests for binary file string loading."""

    def test_ftxt_binary(self):
        data = _build_ftxt(["Hello", "World"])
        with tempfile.NamedTemporaryFile(
            suffix=".bin", delete=False
        ) as f:
            f.write(data)
            path = f.name

        try:
            strings = load_strings_from_binary(path, mode="ftxt")
            self.assertEqual(len(strings), 2)
            self.assertIn("Hello", strings.values())
            self.assertIn("World", strings.values())
        finally:
            os.unlink(path)

    def test_missing_mode_raises(self):
        with self.assertRaises(ValueError):
            load_strings("nonexistent.bin", mode=None)

    def test_missing_xpath_raises(self):
        with self.assertRaises(ValueError):
            load_strings_from_binary("test.bin", mode="xpath", xpath=None)


class TestLoadStringsAutoDetect(unittest.TestCase):
    """Tests for load_strings auto-detection."""

    def test_csv_detected(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline="", encoding="utf-8"
        ) as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            writer.writerow(["0x0@test.bin", "Text", "Texte"])
            path = f.name

        try:
            strings = load_strings(path)
            self.assertEqual(strings["0x0"], "Texte")
        finally:
            os.unlink(path)

    def test_json_detected(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            _write_json(f.name, [
                {"location": "0x0@test.bin", "source": "Text", "target": "Texte"},
            ])
            path = f.name

        try:
            strings = load_strings(path)
            self.assertEqual(strings["0x0"], "Texte")
        finally:
            os.unlink(path)

    def test_binary_requires_mode(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00" * 16)
            path = f.name

        try:
            with self.assertRaises(ValueError):
                load_strings(path)
        finally:
            os.unlink(path)


class TestDiffCSVIntegration(unittest.TestCase):
    """Integration tests comparing two CSV files."""

    def test_identical_csvs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path_a = os.path.join(tmpdir, "a.csv")
            path_b = os.path.join(tmpdir, "b.csv")
            rows = [
                ["0x0@file.bin", "Hello", "Hello"],
                ["0x4@file.bin", "World", "World"],
            ]
            _write_csv(path_a, rows)
            _write_csv(path_b, rows)

            a = load_strings(path_a)
            b = load_strings(path_b)
            result = diff_strings(a, b, path_a, path_b)

            self.assertEqual(len(result.modified), 0)
            self.assertEqual(len(result.added), 0)
            self.assertEqual(len(result.removed), 0)
            self.assertEqual(result.unchanged, 2)

    def test_modified_csvs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path_a = os.path.join(tmpdir, "a.csv")
            path_b = os.path.join(tmpdir, "b.csv")
            _write_csv(path_a, [
                ["0x0@file.bin", "Hello", "Hello"],
                ["0x4@file.bin", "World", "World"],
            ])
            _write_csv(path_b, [
                ["0x0@file.bin", "Hello", "Bonjour"],
                ["0x4@file.bin", "World", "Monde"],
            ])

            a = load_strings(path_a)
            b = load_strings(path_b)
            result = diff_strings(a, b, path_a, path_b)

            self.assertEqual(len(result.modified), 2)
            self.assertEqual(result.modified[0], ("0x0", "Hello", "Bonjour"))

    def test_added_and_removed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path_a = os.path.join(tmpdir, "a.csv")
            path_b = os.path.join(tmpdir, "b.csv")
            _write_csv(path_a, [
                ["0x0@file.bin", "Keep", "Keep"],
                ["0x4@file.bin", "Remove", "Remove"],
            ])
            _write_csv(path_b, [
                ["0x0@file.bin", "Keep", "Keep"],
                ["0x8@file.bin", "Added", "Added"],
            ])

            a = load_strings(path_a)
            b = load_strings(path_b)
            result = diff_strings(a, b, path_a, path_b)

            self.assertEqual(result.unchanged, 1)
            self.assertEqual(len(result.added), 1)
            self.assertEqual(result.added[0], ("0x8", "Added"))
            self.assertEqual(len(result.removed), 1)
            self.assertEqual(result.removed[0], ("0x4", "Remove"))


class TestDiffJSONIntegration(unittest.TestCase):
    """Integration tests comparing two JSON files."""

    def test_identical_jsons(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path_a = os.path.join(tmpdir, "a.json")
            path_b = os.path.join(tmpdir, "b.json")
            entries = [
                {"location": "0x0@file.bin", "source": "Hello", "target": "Hello"},
                {"location": "0x4@file.bin", "source": "World", "target": "World"},
            ]
            _write_json(path_a, entries)
            _write_json(path_b, entries)

            a = load_strings(path_a)
            b = load_strings(path_b)
            result = diff_strings(a, b, path_a, path_b)

            self.assertEqual(len(result.modified), 0)
            self.assertEqual(len(result.added), 0)
            self.assertEqual(len(result.removed), 0)
            self.assertEqual(result.unchanged, 2)

    def test_modified_jsons(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path_a = os.path.join(tmpdir, "a.json")
            path_b = os.path.join(tmpdir, "b.json")
            _write_json(path_a, [
                {"location": "0x0@file.bin", "source": "Hello", "target": "Hello"},
                {"location": "0x4@file.bin", "source": "World", "target": "World"},
            ])
            _write_json(path_b, [
                {"location": "0x0@file.bin", "source": "Hello", "target": "Bonjour"},
                {"location": "0x4@file.bin", "source": "World", "target": "Monde"},
            ])

            a = load_strings(path_a)
            b = load_strings(path_b)
            result = diff_strings(a, b, path_a, path_b)

            self.assertEqual(len(result.modified), 2)
            self.assertEqual(result.modified[0], ("0x0", "Hello", "Bonjour"))

    def test_csv_vs_json(self):
        """Cross-format diff: CSV file A vs JSON file B."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path_a = os.path.join(tmpdir, "a.csv")
            path_b = os.path.join(tmpdir, "b.json")
            _write_csv(path_a, [
                ["0x0@file.bin", "Hello", "Hello"],
                ["0x4@file.bin", "World", "World"],
            ])
            _write_json(path_b, [
                {"location": "0x0@file.bin", "source": "Hello", "target": "Bonjour"},
                {"location": "0x4@file.bin", "source": "World", "target": "Monde"},
            ])

            a = load_strings(path_a)
            b = load_strings(path_b)
            result = diff_strings(a, b, path_a, path_b)

            self.assertEqual(len(result.modified), 2)
            self.assertEqual(result.unchanged, 0)


class TestDiffFTXTIntegration(unittest.TestCase):
    """Integration test: compare two FTXT binary files."""

    def test_ftxt_diff(self):
        data_a = _build_ftxt(["Alpha", "Beta"])
        data_b = _build_ftxt(["Alpha", "Gamma", "Delta"])

        with tempfile.TemporaryDirectory() as tmpdir:
            path_a = os.path.join(tmpdir, "a.bin")
            path_b = os.path.join(tmpdir, "b.bin")
            with open(path_a, "wb") as f:
                f.write(data_a)
            with open(path_b, "wb") as f:
                f.write(data_b)

            a = load_strings(path_a, mode="ftxt")
            b = load_strings(path_b, mode="ftxt")
            result = diff_strings(a, b, path_a, path_b)

            # Both have a string at offset 0x10 (first string after 16-byte header)
            # The second string will be at different offsets due to different content
            total_changes = len(result.modified) + len(result.added) + len(result.removed)
            self.assertGreater(total_changes, 0)


class TestDiffResultDataclass(unittest.TestCase):
    """Tests for DiffResult construction."""

    def test_defaults(self):
        result = DiffResult(file_a="a", file_b="b")
        self.assertEqual(result.modified, [])
        self.assertEqual(result.added, [])
        self.assertEqual(result.removed, [])
        self.assertEqual(result.unchanged, 0)

    def test_with_values(self):
        result = DiffResult(
            file_a="x.csv",
            file_b="y.csv",
            modified=[("0x0", "a", "b")],
            added=[("0x4", "c")],
            removed=[("0x8", "d")],
            unchanged=10,
        )
        self.assertEqual(result.file_a, "x.csv")
        self.assertEqual(len(result.modified), 1)
        self.assertEqual(len(result.added), 1)
        self.assertEqual(len(result.removed), 1)
        self.assertEqual(result.unchanged, 10)


if __name__ == "__main__":
    unittest.main()
