"""
Tests for FTXT and quest file support.

Tests extraction, round-trip import/export, and edge cases for:
- FTXT standalone text files (magic 0x000B0000)
- Individual quest .bin files
"""
import csv
import os
import struct
import tempfile
import unittest

from src import (
    encode_game_string,
    decode_game_string,
    is_ftxt_file,
    extract_ftxt,
    extract_ftxt_data,
    extract_quest_file,
    extract_quest_file_data,
    QUEST_TEXT_LABELS,
    encode_ecd,
    compress_jkr_hfi,
)
from src.common import FTXT_MAGIC, FTXT_HEADER_SIZE
from src.export import (
    export_as_csv,
    extract_ftxt_file,
    extract_single_quest_file,
    extract_quest_files,
)
from src.import_data import (
    get_new_strings,
    import_ftxt_from_csv,
    rebuild_ftxt,
)


def build_ftxt(strings: list[str]) -> bytes:
    """
    Build a synthetic FTXT binary for testing.

    :param strings: List of strings to include
    :return: Complete FTXT binary data
    """
    # Encode all strings
    encoded_parts = []
    for s in strings:
        encoded_parts.append(encode_game_string(s) + b"\x00")
    text_block = b"".join(encoded_parts)

    # Build 16-byte header
    header = bytearray(FTXT_HEADER_SIZE)
    struct.pack_into("<I", header, 0x00, FTXT_MAGIC)       # magic
    # 6 bytes padding (0x04-0x09)
    struct.pack_into("<H", header, 0x0A, len(strings))     # string count
    struct.pack_into("<I", header, 0x0C, len(text_block))  # text block size

    return bytes(header) + text_block


def build_quest_file(
    strings: list[str | None],
    quest_type_flags_offset: int = 0x00,
    quest_strings_offset: int = 0xE8
) -> bytes:
    """
    Build a synthetic quest .bin file for testing.

    Layout:
    - 0x00: questTypeFlagsPtr -> points to main quest props block
    - main quest props block: at quest_strings_offset, QuestStringsPtr -> text block
    - text block: 8 consecutive u32 pointers to null-terminated strings
    - strings follow the text block

    :param strings: List of 8 strings (or None for empty slots)
    :param quest_type_flags_offset: Offset of questTypeFlagsPtr in header
    :param quest_strings_offset: Offset of QuestStringsPtr in main quest props
    :return: Complete quest binary data
    """
    assert len(strings) == 8, "Quest files have exactly 8 text strings"

    # Calculate layout
    header_size = quest_type_flags_offset + 4
    # Main quest props block right after header (needs to be large enough)
    main_props_start = max(header_size, 4)
    main_props_size = quest_strings_offset + 4
    text_block_start = main_props_start + main_props_size
    text_block_size = 8 * 4  # 8 pointers
    strings_start = text_block_start + text_block_size

    # Encode strings and compute offsets
    encoded = []
    string_offsets = []
    current = strings_start
    for s in strings:
        if s is not None:
            enc = encode_game_string(s) + b"\x00"
            string_offsets.append(current)
            encoded.append(enc)
            current += len(enc)
        else:
            string_offsets.append(0)

    # Build binary
    data = bytearray(strings_start)

    # Header: questTypeFlagsPtr
    struct.pack_into("<I", data, quest_type_flags_offset, main_props_start)

    # Main quest props: QuestStringsPtr
    struct.pack_into("<I", data, main_props_start + quest_strings_offset, text_block_start)

    # Text block: 8 string pointers
    for i, offset in enumerate(string_offsets):
        struct.pack_into("<I", data, text_block_start + i * 4, offset)

    # Append strings
    for enc in encoded:
        data.extend(enc)

    return bytes(data)


class TestIsFtxtFile(unittest.TestCase):
    """Tests for FTXT file detection."""

    def test_valid_ftxt(self):
        """Test detection of valid FTXT file."""
        data = build_ftxt(["Hello"])
        self.assertTrue(is_ftxt_file(data))

    def test_empty_ftxt(self):
        """Test detection of FTXT with no strings."""
        data = build_ftxt([])
        self.assertTrue(is_ftxt_file(data))

    def test_not_ftxt(self):
        """Test rejection of non-FTXT data."""
        data = b"\x00\x00\x00\x00" + b"\x00" * 12
        self.assertFalse(is_ftxt_file(data))

    def test_too_short(self):
        """Test rejection of data too short to be FTXT."""
        self.assertFalse(is_ftxt_file(b"\x00\x0B"))
        self.assertFalse(is_ftxt_file(b""))

    def test_ecd_magic_rejected(self):
        """Test that ECD magic is not confused with FTXT."""
        data = struct.pack("<I", 0x1A646365) + b"\x00" * 12
        self.assertFalse(is_ftxt_file(data))


class TestExtractFtxtData(unittest.TestCase):
    """Tests for FTXT data extraction."""

    def test_single_string(self):
        """Test extracting a single ASCII string."""
        data = build_ftxt(["Hello"])
        result = extract_ftxt_data(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["text"], "Hello")
        self.assertEqual(result[0]["offset"], FTXT_HEADER_SIZE)

    def test_multiple_strings(self):
        """Test extracting multiple strings."""
        strings = ["Item A", "Item B", "Item C"]
        data = build_ftxt(strings)
        result = extract_ftxt_data(data)
        self.assertEqual(len(result), 3)
        for i, s in enumerate(strings):
            self.assertEqual(result[i]["text"], s)

    def test_japanese_strings(self):
        """Test extracting Japanese Shift-JIS text."""
        strings = ["テスト", "武器", "防具"]
        data = build_ftxt(strings)
        result = extract_ftxt_data(data)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["text"], "テスト")
        self.assertEqual(result[1]["text"], "武器")
        self.assertEqual(result[2]["text"], "防具")

    def test_empty_strings(self):
        """Test extracting empty strings."""
        strings = ["Hello", "", "World"]
        data = build_ftxt(strings)
        result = extract_ftxt_data(data)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["text"], "Hello")
        self.assertEqual(result[1]["text"], "")
        self.assertEqual(result[2]["text"], "World")

    def test_no_strings(self):
        """Test FTXT with zero string count."""
        data = build_ftxt([])
        result = extract_ftxt_data(data)
        self.assertEqual(len(result), 0)

    def test_offsets_are_sequential(self):
        """Test that offsets match the actual byte positions."""
        strings = ["AB", "CD", "EF"]
        data = build_ftxt(strings)
        result = extract_ftxt_data(data)
        # "AB" at 0x10, "CD" at 0x10+3, "EF" at 0x10+6
        self.assertEqual(result[0]["offset"], 0x10)
        self.assertEqual(result[1]["offset"], 0x10 + 3)  # "AB\0" = 3 bytes
        self.assertEqual(result[2]["offset"], 0x10 + 6)  # "CD\0" = 3 bytes

    def test_not_ftxt_raises(self):
        """Test that non-FTXT data raises ValueError."""
        data = b"\xFF\xFF\xFF\xFF" + b"\x00" * 12
        with self.assertRaises(ValueError):
            extract_ftxt_data(data)

    def test_too_small_raises(self):
        """Test that truncated FTXT header raises ValueError."""
        data = struct.pack("<I", FTXT_MAGIC) + b"\x00" * 4  # Only 8 bytes
        with self.assertRaises(ValueError):
            extract_ftxt_data(data)


class TestExtractFtxt(unittest.TestCase):
    """Tests for FTXT file extraction (from file path)."""

    def test_extract_from_file(self):
        """Test extracting FTXT from a file on disk."""
        strings = ["Test1", "Test2"]
        data = build_ftxt(strings)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(data)
            temp_path = f.name

        try:
            result = extract_ftxt(temp_path)
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["text"], "Test1")
            self.assertEqual(result[1]["text"], "Test2")
        finally:
            os.unlink(temp_path)

    def test_extract_encrypted_ftxt(self):
        """Test extracting FTXT from an ECD-encrypted file."""
        strings = ["Encrypted", "Text"]
        ftxt_data = build_ftxt(strings)
        encrypted = encode_ecd(ftxt_data)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(encrypted)
            temp_path = f.name

        try:
            result = extract_ftxt(temp_path)
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["text"], "Encrypted")
            self.assertEqual(result[1]["text"], "Text")
        finally:
            os.unlink(temp_path)

    def test_extract_compressed_ftxt(self):
        """Test extracting FTXT from a JKR-compressed file."""
        strings = ["Compressed", "Data"]
        ftxt_data = build_ftxt(strings)
        compressed = compress_jkr_hfi(ftxt_data)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(compressed)
            temp_path = f.name

        try:
            result = extract_ftxt(temp_path)
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["text"], "Compressed")
            self.assertEqual(result[1]["text"], "Data")
        finally:
            os.unlink(temp_path)

    def test_not_ftxt_raises(self):
        """Test that non-FTXT file raises ValueError."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00" * 32)
            temp_path = f.name

        try:
            with self.assertRaises(ValueError):
                extract_ftxt(temp_path)
        finally:
            os.unlink(temp_path)


class TestExtractFtxtFile(unittest.TestCase):
    """Tests for FTXT export to CSV."""

    def test_export_csv(self):
        """Test FTXT extraction to CSV file."""
        strings = ["Item1", "Item2", "Item3"]
        data = build_ftxt(strings)

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "test.bin")
            with open(input_path, "wb") as f:
                f.write(data)

            csv_path, ref_path = extract_ftxt_file(
                input_path, output_dir=tmpdir
            )

            self.assertTrue(os.path.exists(csv_path))
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
                self.assertEqual(header, ["location", "source", "target"])
                rows = list(reader)
                self.assertEqual(len(rows), 3)
                self.assertEqual(rows[0][1], "Item1")
                self.assertEqual(rows[1][1], "Item2")
                self.assertEqual(rows[2][1], "Item3")


class TestFtxtImport(unittest.TestCase):
    """Tests for FTXT CSV-to-binary import."""

    def test_rebuild_ftxt(self):
        """Test rebuilding FTXT with translated strings."""
        original_strings = ["Hello", "World", "Test"]
        data = build_ftxt(original_strings)

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            output_path = os.path.join(tmpdir, "output.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            # Translate "World" at offset 0x16 (0x10 + len("Hello\0"))
            new_strings = [(0x10 + 6, "Monde")]
            rebuild_ftxt(source_path, new_strings, output_path)

            # Verify the rebuilt file
            with open(output_path, "rb") as f:
                result = extract_ftxt_data(f.read())
            self.assertEqual(len(result), 3)
            self.assertEqual(result[0]["text"], "Hello")
            self.assertEqual(result[1]["text"], "Monde")
            self.assertEqual(result[2]["text"], "Test")

    def test_rebuild_ftxt_header_updated(self):
        """Test that rebuilt FTXT updates text block size in header."""
        original_strings = ["AB"]
        data = build_ftxt(original_strings)

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            output_path = os.path.join(tmpdir, "output.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            # Replace with longer string
            new_strings = [(FTXT_HEADER_SIZE, "LongerString")]
            rebuild_ftxt(source_path, new_strings, output_path)

            with open(output_path, "rb") as f:
                rebuilt = f.read()

            # Check header
            magic = struct.unpack_from("<I", rebuilt, 0)[0]
            self.assertEqual(magic, FTXT_MAGIC)
            string_count = struct.unpack_from("<H", rebuilt, 0x0A)[0]
            self.assertEqual(string_count, 1)
            text_block_size = struct.unpack_from("<I", rebuilt, 0x0C)[0]
            expected_size = len(encode_game_string("LongerString")) + 1
            self.assertEqual(text_block_size, expected_size)

    def test_round_trip_ftxt(self):
        """Test full round-trip: extract → edit CSV → reimport."""
        strings = ["Alpha", "Beta", "Gamma"]
        data = build_ftxt(strings)

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            # Extract
            csv_path, _ = extract_ftxt_file(
                source_path, output_dir=tmpdir
            )

            # Edit CSV: change "Beta" to "Bêta"
            rows = []
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                for row in reader:
                    rows.append(row)
            for row in rows[1:]:
                if row[1] == "Beta":
                    row[2] = "Bêta"  # ê is not in Shift-JIS, use ASCII
            # Actually use a Shift-JIS compatible replacement
            for row in rows[1:]:
                if row[1] == "Beta":
                    row[2] = "BETA"

            edited_csv = os.path.join(tmpdir, "edited.csv")
            with open(edited_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerows(rows)

            # Import
            output_path = os.path.join(tmpdir, "modified.bin")
            import_ftxt_from_csv(edited_csv, source_path, output_path)

            # Verify
            with open(output_path, "rb") as f:
                result = extract_ftxt_data(f.read())
            self.assertEqual(len(result), 3)
            self.assertEqual(result[0]["text"], "Alpha")
            self.assertEqual(result[1]["text"], "BETA")
            self.assertEqual(result[2]["text"], "Gamma")

    def test_import_no_changes(self):
        """Test that import with no changes returns None."""
        strings = ["Hello"]
        data = build_ftxt(strings)

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            csv_path, _ = extract_ftxt_file(
                source_path, output_dir=tmpdir
            )

            # No edits - source == target
            result = import_ftxt_from_csv(csv_path, source_path)
            self.assertIsNone(result)


class TestExtractQuestFileData(unittest.TestCase):
    """Tests for quest file text extraction."""

    def test_all_eight_strings(self):
        """Test extracting all 8 text strings from a quest file."""
        strings = [
            "Title", "Main Obj", "Sub A", "Sub B",
            "Success", "Fail", "Contractor", "Description"
        ]
        data = build_quest_file(strings)
        result = extract_quest_file_data(data)

        self.assertEqual(len(result), 1)
        text = result[0]["text"]
        for s in strings:
            self.assertIn(s, text)
        # 7 joins (8 strings - 1)
        self.assertEqual(text.count("<join"), 7)

    def test_partial_strings(self):
        """Test quest with some null string pointers."""
        strings = ["Title", "Main Obj", None, None, None, None, None, "Description"]
        data = build_quest_file(strings)
        result = extract_quest_file_data(data)

        self.assertEqual(len(result), 1)
        text = result[0]["text"]
        self.assertIn("Title", text)
        self.assertIn("Main Obj", text)
        self.assertIn("Description", text)
        # Only 2 joins (3 non-null strings - 1)
        self.assertEqual(text.count("<join"), 2)

    def test_title_only(self):
        """Test quest with only a title."""
        strings = ["Solo Title", None, None, None, None, None, None, None]
        data = build_quest_file(strings)
        result = extract_quest_file_data(data)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["text"], "Solo Title")
        self.assertNotIn("<join", result[0]["text"])

    def test_all_null_strings(self):
        """Test quest where all text pointers are null."""
        strings = [None, None, None, None, None, None, None, None]
        data = build_quest_file(strings)
        result = extract_quest_file_data(data)
        self.assertEqual(len(result), 0)

    def test_japanese_quest_text(self):
        """Test quest with Japanese text."""
        strings = [
            "テスト討伐", "メインの説明", None, None,
            "成功条件", "失敗条件", "依頼人", "詳細説明"
        ]
        data = build_quest_file(strings)
        result = extract_quest_file_data(data)

        self.assertEqual(len(result), 1)
        self.assertIn("テスト討伐", result[0]["text"])
        self.assertIn("メインの説明", result[0]["text"])
        self.assertIn("依頼人", result[0]["text"])

    def test_zero_quest_type_flags_ptr(self):
        """Test quest file with null questTypeFlagsPtr."""
        data = b"\x00" * 256
        result = extract_quest_file_data(data)
        self.assertEqual(len(result), 0)


class TestExtractQuestFile(unittest.TestCase):
    """Tests for quest file extraction from disk."""

    def test_extract_from_file(self):
        """Test extracting quest text from a file on disk."""
        strings = ["Quest Title", "Objective", None, None,
                    None, None, "NPC", "Full Description"]
        data = build_quest_file(strings)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(data)
            temp_path = f.name

        try:
            result = extract_quest_file(temp_path)
            self.assertEqual(len(result), 1)
            self.assertIn("Quest Title", result[0]["text"])
            self.assertIn("Full Description", result[0]["text"])
        finally:
            os.unlink(temp_path)

    def test_extract_encrypted_quest(self):
        """Test extracting quest from ECD-encrypted file."""
        strings = ["Encrypted Quest", "Obj", None, None,
                    None, None, None, None]
        quest_data = build_quest_file(strings)
        encrypted = encode_ecd(quest_data)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(encrypted)
            temp_path = f.name

        try:
            result = extract_quest_file(temp_path)
            self.assertEqual(len(result), 1)
            self.assertIn("Encrypted Quest", result[0]["text"])
        finally:
            os.unlink(temp_path)


class TestExtractSingleQuestFile(unittest.TestCase):
    """Tests for single quest file CSV export."""

    def test_export_csv(self):
        """Test quest file extraction to CSV."""
        strings = ["Title", "Obj", None, None, None, None, "NPC", "Desc"]
        data = build_quest_file(strings)

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "quest001.bin")
            with open(input_path, "wb") as f:
                f.write(data)

            csv_path, ref_path = extract_single_quest_file(
                input_path, output_dir=tmpdir
            )

            self.assertTrue(os.path.exists(csv_path))
            self.assertIn("quest-quest001", csv_path)


class TestExtractQuestFiles(unittest.TestCase):
    """Tests for batch quest file extraction."""

    def test_batch_extract(self):
        """Test batch extraction from directory of quest files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            quest_dir = os.path.join(tmpdir, "quests")
            output_dir = os.path.join(tmpdir, "output")
            os.makedirs(quest_dir)

            # Create 3 quest files
            for i in range(3):
                strings = [f"Quest {i}", f"Obj {i}", None, None,
                           None, None, None, None]
                data = build_quest_file(strings)
                with open(os.path.join(quest_dir, f"quest{i:03d}.bin"), "wb") as f:
                    f.write(data)

            files = extract_quest_files(quest_dir, output_dir)
            self.assertEqual(len(files), 3)
            for f in files:
                self.assertTrue(os.path.exists(f))

    def test_batch_skips_non_bin(self):
        """Test that batch extraction skips non-.bin files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            quest_dir = os.path.join(tmpdir, "quests")
            output_dir = os.path.join(tmpdir, "output")
            os.makedirs(quest_dir)

            # Create one quest file and one non-bin file
            strings = ["Quest", "Obj", None, None, None, None, None, None]
            data = build_quest_file(strings)
            with open(os.path.join(quest_dir, "quest001.bin"), "wb") as f:
                f.write(data)
            with open(os.path.join(quest_dir, "readme.txt"), "w") as f:
                f.write("not a quest")

            files = extract_quest_files(quest_dir, output_dir)
            self.assertEqual(len(files), 1)

    def test_nonexistent_dir_raises(self):
        """Test that nonexistent directory raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            extract_quest_files("/nonexistent/path")


class TestQuestFileImport(unittest.TestCase):
    """Tests for quest file CSV-to-binary import (uses standard pointer append)."""

    def test_import_modifies_pointer(self):
        """Test that CSV import updates quest string pointers."""
        from src.import_data import import_from_csv

        strings = ["Original Title", "Obj", None, None,
                    None, None, None, None]
        data = build_quest_file(strings)

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "quest.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            # Extract to CSV
            csv_path, _ = extract_single_quest_file(
                source_path, output_dir=tmpdir
            )

            # Edit CSV: change title
            rows = []
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                for row in reader:
                    rows.append(row)
            # The first data row contains joined strings; modify the target
            if len(rows) > 1:
                # Replace the joined text with modified version
                rows[1][2] = rows[1][2].replace("Original Title", "New Title")

            edited_csv = os.path.join(tmpdir, "edited.csv")
            with open(edited_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerows(rows)

            # Import back
            output_path = os.path.join(tmpdir, "modified.bin")
            result = import_from_csv(edited_csv, source_path, output_path)

            self.assertIsNotNone(result)
            self.assertTrue(os.path.exists(output_path))


class TestQuestTextLabels(unittest.TestCase):
    """Tests for quest text label constants."""

    def test_labels_count(self):
        """Test that there are exactly 8 quest text labels."""
        self.assertEqual(len(QUEST_TEXT_LABELS), 8)

    def test_labels_content(self):
        """Test that labels match the quest file format."""
        self.assertEqual(QUEST_TEXT_LABELS[0], "title")
        self.assertEqual(QUEST_TEXT_LABELS[7], "description")
        self.assertIn("contractor", QUEST_TEXT_LABELS)
        self.assertIn("successCond", QUEST_TEXT_LABELS)


if __name__ == "__main__":
    unittest.main()
