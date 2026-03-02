"""
Tests for scenario file extraction and import.

Tests extraction, round-trip import/export, and edge cases for
scenario binary files containing story system text.
"""
import csv
import json
import os
import struct
import tempfile
import unittest

from src import (
    encode_game_string,
    extract_scenario_file,
    extract_scenario_file_data,
)
from src.export import (
    export_as_csv,
    extract_scenario_file as extract_scenario_file_export,
    extract_scenario_files,
)
from src.import_data import (
    get_new_strings,
    import_scenario_from_csv,
    rebuild_scenario_file,
)
from src.jkr_compress import compress_jkr_hfi


def build_scenario_file(
    chunk0_strings: list[str] | None = None,
    chunk1_strings: list[str] | None = None,
    chunk0_inline: bool = False,
) -> bytes:
    """
    Build a synthetic scenario binary for testing.

    :param chunk0_strings: Strings for chunk0 (quest name/description)
    :param chunk1_strings: Strings for chunk1 (NPC dialog)
    :param chunk0_inline: If True, use inline format for chunk0 instead of sub-header
    :return: Complete scenario binary data
    """
    # Build chunk0 data
    if chunk0_strings is not None:
        if chunk0_inline:
            c0_data = _build_inline_chunk(chunk0_strings)
        else:
            c0_data = _build_subheader_chunk(chunk0_strings, metadata_size=4)
    else:
        c0_data = b""

    # Build chunk1 data
    if chunk1_strings is not None:
        c1_data = _build_subheader_chunk(chunk1_strings, metadata_size=8)
    else:
        c1_data = b""

    # Container: c0_size(u32 BE) + c1_size(u32 BE) + c0_data + c1_data + c2_size(u32 BE)
    header = struct.pack(">II", len(c0_data), len(c1_data))
    c2_size = struct.pack(">I", 0)

    return header + c0_data + c1_data + c2_size


def _build_subheader_chunk(strings: list[str], metadata_size: int = 4) -> bytes:
    """Build a chunk with sub-header format."""
    # Encode strings
    encoded_strings = []
    for s in strings:
        encoded_strings.append(encode_game_string(s) + b"\x00")

    # Calculate total string data size
    string_data = b"".join(encoded_strings) + b"\xff"  # FF sentinel

    # Sub-header: type(u8)=1, pad(u8)=0, size(u16 LE), entry_count(u8), unk(u8)=0,
    #             metadata_total(u8), unk(u8)=0
    total_size = 8 + metadata_size + len(string_data)
    sub_header = struct.pack(
        "<BBHBBBB",
        1, 0,  # type, pad
        total_size,  # size (u16 LE)
        len(strings), 0,  # entry_count, unk
        metadata_size, 0,  # metadata_total, unk
    )

    # Metadata: just zero-filled
    metadata = b"\x00" * metadata_size

    return sub_header + metadata + string_data


def _build_inline_chunk(strings: list[str]) -> bytes:
    """Build a chunk with inline format: {u8 index}{string}{00}."""
    data = bytearray()
    for i, s in enumerate(strings, start=1):
        data.append(i)  # index byte
        data.extend(encode_game_string(s))
        data.append(0x00)  # null terminator
    return bytes(data)


class TestExtractScenario(unittest.TestCase):
    """Tests for scenario file extraction."""

    def test_chunk0_subheader_single_string(self):
        """Test extraction from chunk0 with sub-header format, single string."""
        data = build_scenario_file(chunk0_strings=["Hello"])
        result = extract_scenario_file_data(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["text"], "Hello")

    def test_chunk0_subheader_multiple_strings(self):
        """Test extraction from chunk0 with multiple strings."""
        data = build_scenario_file(chunk0_strings=["Line1", "Line2", "Line3"])
        result = extract_scenario_file_data(data)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["text"], "Line1")
        self.assertEqual(result[1]["text"], "Line2")
        self.assertEqual(result[2]["text"], "Line3")

    def test_chunk0_inline_format(self):
        """Test extraction from chunk0 with inline format."""
        data = build_scenario_file(chunk0_strings=["Item1", "Item2"], chunk0_inline=True)
        result = extract_scenario_file_data(data)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["text"], "Item1")
        self.assertEqual(result[1]["text"], "Item2")

    def test_chunk1_subheader(self):
        """Test extraction from chunk1 (NPC dialog)."""
        data = build_scenario_file(chunk1_strings=["Dialog1", "Dialog2"])
        result = extract_scenario_file_data(data)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["text"], "Dialog1")
        self.assertEqual(result[1]["text"], "Dialog2")

    def test_combined_chunks(self):
        """Test extraction from both chunk0 and chunk1."""
        data = build_scenario_file(
            chunk0_strings=["Quest1"],
            chunk1_strings=["NPC1", "NPC2"],
        )
        result = extract_scenario_file_data(data)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["text"], "Quest1")
        self.assertEqual(result[1]["text"], "NPC1")
        self.assertEqual(result[2]["text"], "NPC2")

    def test_japanese_text(self):
        """Test extraction of Japanese Shift-JIS text."""
        data = build_scenario_file(chunk0_strings=["テスト", "こんにちは"])
        result = extract_scenario_file_data(data)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["text"], "テスト")
        self.assertEqual(result[1]["text"], "こんにちは")

    def test_empty_file(self):
        """Test extraction from file with no chunks."""
        # Header only: c0=0, c1=0, c2=0
        data = struct.pack(">II", 0, 0) + struct.pack(">I", 0)
        result = extract_scenario_file_data(data)
        self.assertEqual(result, [])

    def test_too_small_data(self):
        """Test with data too small to contain header."""
        result = extract_scenario_file_data(b"\x00\x00")
        self.assertEqual(result, [])

    def test_extract_from_file(self):
        """Test extraction from a file path."""
        data = build_scenario_file(chunk0_strings=["FileTest"])
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(data)
            f.flush()
            try:
                result = extract_scenario_file(f.name)
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]["text"], "FileTest")
            finally:
                os.unlink(f.name)

    def test_special_markers(self):
        """Test extraction preserves @RETURN, @MYNAME, ~C05 markers."""
        text = "Hello @MYNAME!@RETURN~C05test~C00"
        data = build_scenario_file(chunk1_strings=[text])
        result = extract_scenario_file_data(data)
        self.assertEqual(len(result), 1)
        self.assertIn("@MYNAME", result[0]["text"])
        self.assertIn("@RETURN", result[0]["text"])
        self.assertIn("~C05", result[0]["text"])


class TestScenarioCsvExport(unittest.TestCase):
    """Tests for scenario CSV export."""

    def test_export_single_file(self):
        """Test CSV export from a single scenario file."""
        data = build_scenario_file(chunk0_strings=["Line1", "Line2"])
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "scenario.bin")
            with open(input_path, "wb") as f:
                f.write(data)

            csv_path, ref_path, json_path = extract_scenario_file_export(
                input_path, output_dir=tmpdir
            )
            self.assertTrue(os.path.exists(csv_path))
            self.assertIn("scenario-scenario", csv_path)

            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
                self.assertEqual(header, ["location", "source", "target"])
                rows = list(reader)
                self.assertEqual(len(rows), 2)

    def test_export_json(self):
        """Test JSON export from a single scenario file."""
        data = build_scenario_file(chunk0_strings=["Line1", "Line2"])
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "scenario.bin")
            with open(input_path, "wb") as f:
                f.write(data)

            csv_path, ref_path, json_path = extract_scenario_file_export(
                input_path, output_dir=tmpdir
            )
            self.assertTrue(os.path.exists(json_path))

            with open(json_path, "r", encoding="utf-8") as f:
                json_data = json.load(f)

            self.assertIn("metadata", json_data)
            self.assertIn("strings", json_data)
            self.assertEqual(len(json_data["strings"]), 2)
            self.assertEqual(json_data["strings"][0]["source"], "Line1")
            self.assertEqual(json_data["strings"][1]["source"], "Line2")
            # source == target when freshly extracted
            self.assertEqual(
                json_data["strings"][0]["source"],
                json_data["strings"][0]["target"],
            )

    def test_batch_export(self):
        """Test batch extraction from directory."""
        data1 = build_scenario_file(chunk0_strings=["Hello"])
        data2 = build_scenario_file(chunk1_strings=["World"])
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = os.path.join(tmpdir, "input")
            output_dir = os.path.join(tmpdir, "output")
            os.makedirs(input_dir)

            with open(os.path.join(input_dir, "s1.bin"), "wb") as f:
                f.write(data1)
            with open(os.path.join(input_dir, "s2.bin"), "wb") as f:
                f.write(data2)
            with open(os.path.join(input_dir, "readme.txt"), "w") as f:
                f.write("not a bin file")

            files = extract_scenario_files(input_dir, output_dir)
            self.assertEqual(len(files), 2)
            for path in files:
                self.assertTrue(os.path.exists(path))

    def test_batch_export_generates_json(self):
        """Test batch extraction also generates JSON files alongside CSV."""
        data = build_scenario_file(chunk0_strings=["Hello"])
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = os.path.join(tmpdir, "input")
            output_dir = os.path.join(tmpdir, "output")
            os.makedirs(input_dir)

            with open(os.path.join(input_dir, "s1.bin"), "wb") as f:
                f.write(data)

            files = extract_scenario_files(input_dir, output_dir)
            self.assertEqual(len(files), 1)

            # Check that JSON was also generated
            json_path = files[0].replace(".csv", ".json")
            self.assertTrue(os.path.exists(json_path))

            with open(json_path, "r", encoding="utf-8") as f:
                json_data = json.load(f)
            self.assertEqual(len(json_data["strings"]), 1)
            self.assertEqual(json_data["strings"][0]["source"], "Hello")

    def test_batch_export_missing_dir(self):
        """Test batch extraction raises on missing directory."""
        with self.assertRaises(FileNotFoundError):
            extract_scenario_files("/nonexistent/dir")


class TestScenarioRebuild(unittest.TestCase):
    """Tests for scenario file rebuild."""

    def test_no_change_roundtrip(self):
        """Test rebuild with no translations preserves text."""
        data = build_scenario_file(chunk0_strings=["Hello", "World"])

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            output_path = os.path.join(tmpdir, "output.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            rebuild_scenario_file(source_path, [], output_path)

            result = extract_scenario_file(output_path)
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["text"], "Hello")
            self.assertEqual(result[1]["text"], "World")

    def test_translate_shorter_string(self):
        """Test rebuild with a shorter replacement string."""
        data = build_scenario_file(chunk0_strings=["LongString", "Other"])

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            output_path = os.path.join(tmpdir, "output.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            entries = extract_scenario_file_data(data)
            offset = entries[0]["offset"]
            rebuild_scenario_file(
                source_path,
                [(offset, "Short")],
                output_path,
            )

            result = extract_scenario_file(output_path)
            self.assertEqual(result[0]["text"], "Short")
            self.assertEqual(result[1]["text"], "Other")

    def test_translate_same_length(self):
        """Test rebuild with same-length replacement."""
        data = build_scenario_file(chunk0_strings=["AAAA", "BBBB"])

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            output_path = os.path.join(tmpdir, "output.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            entries = extract_scenario_file_data(data)
            offset = entries[0]["offset"]
            rebuild_scenario_file(
                source_path,
                [(offset, "CCCC")],
                output_path,
            )

            result = extract_scenario_file(output_path)
            self.assertEqual(result[0]["text"], "CCCC")
            self.assertEqual(result[1]["text"], "BBBB")


class TestScenarioFullRoundTrip(unittest.TestCase):
    """End-to-end round-trip tests: extract -> CSV -> edit -> import -> re-extract."""

    def test_full_roundtrip(self):
        """Test complete extract -> edit CSV -> import -> verify cycle."""
        data = build_scenario_file(
            chunk0_strings=["Original1", "Original2"],
            chunk1_strings=["Dialog1"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            # Step 1: Extract to CSV
            csv_path, _, _ = extract_scenario_file_export(
                source_path, output_dir=tmpdir
            )

            # Step 2: Modify CSV - change target for first entry
            rows = []
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
                for row in reader:
                    rows.append(row)

            # Translate first entry (shorter replacement)
            rows[0][2] = "New1"

            edited_csv = os.path.join(tmpdir, "edited.csv")
            with open(edited_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(header)
                for row in rows:
                    writer.writerow(row)

            # Step 3: Import translations
            output_path = import_scenario_from_csv(
                edited_csv, source_path,
                output_path=os.path.join(tmpdir, "modified.bin"),
            )
            self.assertIsNotNone(output_path)

            # Step 4: Re-extract and verify
            result = extract_scenario_file(output_path)
            self.assertEqual(len(result), 3)
            self.assertEqual(result[0]["text"], "New1")
            self.assertEqual(result[1]["text"], "Original2")
            self.assertEqual(result[2]["text"], "Dialog1")

    def test_json_roundtrip(self):
        """Test complete extract -> edit JSON -> import -> verify cycle."""
        data = build_scenario_file(
            chunk0_strings=["Original1", "Original2"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            # Step 1: Extract (generates CSV + JSON)
            csv_path, _, json_path = extract_scenario_file_export(
                source_path, output_dir=tmpdir
            )

            # Step 2: Edit JSON - change target for first entry
            with open(json_path, "r", encoding="utf-8") as f:
                json_data = json.load(f)

            json_data["strings"][0]["target"] = "New1"

            edited_json = os.path.join(tmpdir, "edited.json")
            with open(edited_json, "w", encoding="utf-8") as f:
                json.dump(json_data, f, ensure_ascii=False)

            # Step 3: Import from JSON
            output_path = import_scenario_from_csv(
                edited_json, source_path,
                output_path=os.path.join(tmpdir, "modified.bin"),
            )
            self.assertIsNotNone(output_path)

            # Step 4: Re-extract and verify
            result = extract_scenario_file(output_path)
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["text"], "New1")
            self.assertEqual(result[1]["text"], "Original2")

    def test_no_changes_returns_none(self):
        """Test import with no translations returns None."""
        data = build_scenario_file(chunk0_strings=["Test"])

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            csv_path, _, _ = extract_scenario_file_export(
                source_path, output_dir=tmpdir
            )

            result = import_scenario_from_csv(
                csv_path, source_path,
                output_path=os.path.join(tmpdir, "modified.bin"),
            )
            self.assertIsNone(result)

    def test_inline_format_roundtrip(self):
        """Test round-trip with inline chunk0 format."""
        data = build_scenario_file(
            chunk0_strings=["Item1", "Item2"],
            chunk0_inline=True,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            csv_path, _, _ = extract_scenario_file_export(
                source_path, output_dir=tmpdir
            )

            # Edit
            rows = []
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
                for row in reader:
                    rows.append(row)

            rows[0][2] = "New1"

            edited_csv = os.path.join(tmpdir, "edited.csv")
            with open(edited_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(header)
                for row in rows:
                    writer.writerow(row)

            output_path = import_scenario_from_csv(
                edited_csv, source_path,
                output_path=os.path.join(tmpdir, "modified.bin"),
            )
            self.assertIsNotNone(output_path)

            result = extract_scenario_file(output_path)
            self.assertEqual(result[0]["text"], "New1")
            self.assertEqual(result[1]["text"], "Item2")


if __name__ == "__main__":
    unittest.main()
