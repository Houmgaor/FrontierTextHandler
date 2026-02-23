"""
Tests for NPC dialogue extraction and import.

Tests extraction, round-trip import/export, and edge cases for
stage dialogue binary files containing NPC text.
"""
import csv
import os
import struct
import tempfile
import unittest

from src import (
    encode_game_string,
    decode_game_string,
    extract_npc_dialogue,
    extract_npc_dialogue_data,
    encode_ecd,
    compress_jkr_hfi,
)
from src.common import split_join_text
from src.export import (
    export_as_csv,
    extract_npc_dialogue_file,
    extract_npc_dialogue_files,
)
from src.import_data import (
    get_new_strings,
    import_npc_dialogue_from_csv,
    rebuild_npc_dialogue,
)


def build_npc_dialogue(npcs: list[tuple[int, list[str]]]) -> bytes:
    """
    Build a synthetic NPC dialogue binary for testing.

    :param npcs: List of (npc_id, dialogue_strings) tuples
    :return: Complete NPC dialogue binary data
    """
    num_npcs = len(npcs)
    npc_table_size = (num_npcs + 1) * 8  # +1 for terminator
    blocks_start = npc_table_size

    # Build per-NPC blocks
    npc_blocks: list[bytes] = []
    for npc_id, dialogues in npcs:
        if not dialogues:
            # Empty: header_size = 0
            npc_blocks.append(struct.pack("<I", 0))
            continue

        num_dialogues = len(dialogues)
        header_size = num_dialogues * 4

        # Encode strings
        encoded_strings = []
        for dlg in dialogues:
            encoded_strings.append(encode_game_string(dlg) + b"\x00")

        # Calculate relative pointers from block start
        # Block layout: header_size(4) + pointers(N*4) + strings
        pointers_section_size = 4 + num_dialogues * 4
        string_offset = pointers_section_size
        relative_ptrs = []
        for enc in encoded_strings:
            relative_ptrs.append(string_offset)
            string_offset += len(enc)

        # Build block
        block = bytearray()
        block.extend(struct.pack("<I", header_size))
        for rp in relative_ptrs:
            block.extend(struct.pack("<I", rp))
        for enc in encoded_strings:
            block.extend(enc)
        npc_blocks.append(bytes(block))

    # Compute block offsets
    block_offsets = []
    current_offset = blocks_start
    for block in npc_blocks:
        block_offsets.append(current_offset)
        current_offset += len(block)

    # Write NPC table
    output = bytearray()
    for i, (npc_id, _) in enumerate(npcs):
        output.extend(struct.pack("<I", npc_id))
        output.extend(struct.pack("<I", block_offsets[i]))
    # Terminator
    output.extend(struct.pack("<I", 0xFFFFFFFF))
    output.extend(struct.pack("<I", 0xFFFFFFFF))

    # Write blocks
    for block in npc_blocks:
        output.extend(block)

    return bytes(output)


class TestSplitJoinText(unittest.TestCase):
    """Tests for the split_join_text utility."""

    def test_no_join_tags(self):
        """Test plain text with no join tags."""
        result = split_join_text("Hello world")
        self.assertEqual(result, ["Hello world"])

    def test_single_join(self):
        """Test text with one join tag."""
        result = split_join_text('First<join at="100">Second')
        self.assertEqual(result, ["First", "Second"])

    def test_multiple_joins(self):
        """Test text with multiple join tags."""
        result = split_join_text('A<join at="10">B<join at="20">C')
        self.assertEqual(result, ["A", "B", "C"])

    def test_empty_string(self):
        """Test empty input."""
        result = split_join_text("")
        self.assertEqual(result, [""])


class TestExtractNpcDialogue(unittest.TestCase):
    """Tests for NPC dialogue extraction."""

    def test_single_npc_single_dialogue(self):
        """Test extraction of one NPC with one dialogue line."""
        data = build_npc_dialogue([(1, ["Hello"])])
        result = extract_npc_dialogue_data(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["text"], "Hello")

    def test_single_npc_multiple_dialogues(self):
        """Test extraction of one NPC with multiple dialogue lines."""
        data = build_npc_dialogue([(1, ["Hello", "World", "Test"])])
        result = extract_npc_dialogue_data(data)
        self.assertEqual(len(result), 1)
        # Should contain join tags for the additional dialogues
        parts = split_join_text(result[0]["text"])
        self.assertEqual(parts, ["Hello", "World", "Test"])

    def test_multiple_npcs(self):
        """Test extraction of multiple NPCs."""
        data = build_npc_dialogue([
            (1, ["NPC1 line1", "NPC1 line2"]),
            (2, ["NPC2 line1"]),
            (3, ["NPC3 line1", "NPC3 line2", "NPC3 line3"]),
        ])
        result = extract_npc_dialogue_data(data)
        self.assertEqual(len(result), 3)

        parts0 = split_join_text(result[0]["text"])
        self.assertEqual(parts0, ["NPC1 line1", "NPC1 line2"])

        self.assertEqual(result[1]["text"], "NPC2 line1")

        parts2 = split_join_text(result[2]["text"])
        self.assertEqual(parts2, ["NPC3 line1", "NPC3 line2", "NPC3 line3"])

    def test_japanese_text(self):
        """Test extraction of Japanese Shift-JIS text."""
        data = build_npc_dialogue([(1, ["テスト", "こんにちは"])])
        result = extract_npc_dialogue_data(data)
        self.assertEqual(len(result), 1)
        parts = split_join_text(result[0]["text"])
        self.assertEqual(parts, ["テスト", "こんにちは"])

    def test_empty_npc_table(self):
        """Test extraction with no NPCs (just terminator)."""
        # Just the terminator
        data = struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF)
        result = extract_npc_dialogue_data(data)
        self.assertEqual(result, [])

    def test_empty_dialogue_block(self):
        """Test NPC with empty dialogue (header_size=0)."""
        data = build_npc_dialogue([(1, [])])
        result = extract_npc_dialogue_data(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["text"], "")

    def test_too_small_data(self):
        """Test with data too small to contain anything."""
        result = extract_npc_dialogue_data(b"\x00\x00")
        self.assertEqual(result, [])

    def test_extract_from_file(self):
        """Test extraction from a file path with auto-decrypt/decompress."""
        data = build_npc_dialogue([(5, ["File test"])])
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(data)
            f.flush()
            try:
                result = extract_npc_dialogue(f.name)
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]["text"], "File test")
            finally:
                os.unlink(f.name)

    def test_extract_from_encrypted_file(self):
        """Test extraction auto-decrypts ECD files."""
        data = build_npc_dialogue([(1, ["Encrypted"])])
        encrypted = encode_ecd(data)
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(encrypted)
            f.flush()
            try:
                result = extract_npc_dialogue(f.name)
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]["text"], "Encrypted")
            finally:
                os.unlink(f.name)

    def test_extract_from_compressed_file(self):
        """Test extraction auto-decompresses JKR files."""
        data = build_npc_dialogue([(1, ["Compressed"])])
        compressed = compress_jkr_hfi(data)
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(compressed)
            f.flush()
            try:
                result = extract_npc_dialogue(f.name)
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]["text"], "Compressed")
            finally:
                os.unlink(f.name)


class TestNpcDialogueCsvExport(unittest.TestCase):
    """Tests for NPC dialogue CSV export."""

    def test_export_single_file(self):
        """Test CSV export from a single NPC dialogue file."""
        data = build_npc_dialogue([(1, ["Line1", "Line2"]), (2, ["Line3"])])
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "stage_dialogue.bin")
            with open(input_path, "wb") as f:
                f.write(data)

            csv_path, ref_path, _ = extract_npc_dialogue_file(
                input_path, output_dir=tmpdir
            )
            self.assertTrue(os.path.exists(csv_path))
            self.assertIn("npc-stage_dialogue", csv_path)

            # Verify CSV content
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
                self.assertEqual(header, ["location", "source", "target"])
                rows = list(reader)
                self.assertEqual(len(rows), 2)

    def test_batch_export(self):
        """Test batch extraction from directory."""
        data1 = build_npc_dialogue([(1, ["Hello"])])
        data2 = build_npc_dialogue([(2, ["World"])])
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = os.path.join(tmpdir, "input")
            output_dir = os.path.join(tmpdir, "output")
            os.makedirs(input_dir)

            with open(os.path.join(input_dir, "stage1.bin"), "wb") as f:
                f.write(data1)
            with open(os.path.join(input_dir, "stage2.bin"), "wb") as f:
                f.write(data2)
            # Non-.bin file should be skipped
            with open(os.path.join(input_dir, "readme.txt"), "w") as f:
                f.write("not a bin file")

            files = extract_npc_dialogue_files(input_dir, output_dir)
            self.assertEqual(len(files), 2)
            for path in files:
                self.assertTrue(os.path.exists(path))

    def test_batch_export_missing_dir(self):
        """Test batch extraction raises on missing directory."""
        with self.assertRaises(FileNotFoundError):
            extract_npc_dialogue_files("/nonexistent/dir")


class TestNpcDialogueRebuild(unittest.TestCase):
    """Tests for NPC dialogue binary rebuild."""

    def test_no_change_roundtrip(self):
        """Test rebuild with no translations produces equivalent output."""
        original_strings = [(1, ["Hello", "World"]), (2, ["Test"])]
        data = build_npc_dialogue(original_strings)

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            output_path = os.path.join(tmpdir, "output.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            # No translations
            rebuild_npc_dialogue(source_path, [], output_path)

            # Re-extract and compare
            result = extract_npc_dialogue(output_path)
            self.assertEqual(len(result), 2)
            parts0 = split_join_text(result[0]["text"])
            self.assertEqual(parts0, ["Hello", "World"])
            self.assertEqual(result[1]["text"], "Test")

    def test_translate_single_npc(self):
        """Test rebuild with translation for one NPC."""
        data = build_npc_dialogue([(1, ["Hello", "World"]), (2, ["Test"])])

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            output_path = os.path.join(tmpdir, "output.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            # Extract to get offsets
            entries = extract_npc_dialogue_data(data)
            # Translate NPC 2
            offset = entries[1]["offset"]
            rebuild_npc_dialogue(
                source_path,
                [(offset, "Translated")],
                output_path,
            )

            result = extract_npc_dialogue(output_path)
            self.assertEqual(result[1]["text"], "Translated")
            # NPC 1 unchanged
            parts0 = split_join_text(result[0]["text"])
            self.assertEqual(parts0, ["Hello", "World"])

    def test_translate_with_join_tags(self):
        """Test rebuild with translation containing join tags."""
        data = build_npc_dialogue([(1, ["Line1", "Line2", "Line3"])])

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            output_path = os.path.join(tmpdir, "output.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            entries = extract_npc_dialogue_data(data)
            offset = entries[0]["offset"]
            # Use join tags in translation (as they appear in CSV)
            new_text = 'Translated1<join at="999">Translated2<join at="998">Translated3'
            rebuild_npc_dialogue(
                source_path,
                [(offset, new_text)],
                output_path,
            )

            result = extract_npc_dialogue(output_path)
            parts = split_join_text(result[0]["text"])
            self.assertEqual(parts, ["Translated1", "Translated2", "Translated3"])

    def test_longer_replacement_strings(self):
        """Test rebuild with longer replacement strings."""
        data = build_npc_dialogue([(1, ["Hi"])])

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            output_path = os.path.join(tmpdir, "output.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            entries = extract_npc_dialogue_data(data)
            offset = entries[0]["offset"]
            long_text = "This is a much longer replacement string for testing"
            rebuild_npc_dialogue(
                source_path,
                [(offset, long_text)],
                output_path,
            )

            result = extract_npc_dialogue(output_path)
            self.assertEqual(result[0]["text"], long_text)

    def test_multi_npc_translation(self):
        """Test rebuild with translations for multiple NPCs."""
        data = build_npc_dialogue([
            (1, ["Hello"]),
            (2, ["World"]),
            (3, ["Test"]),
        ])

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            output_path = os.path.join(tmpdir, "output.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            entries = extract_npc_dialogue_data(data)
            translations = [
                (entries[0]["offset"], "Bonjour"),
                (entries[2]["offset"], "Essai"),
            ]
            rebuild_npc_dialogue(source_path, translations, output_path)

            result = extract_npc_dialogue(output_path)
            self.assertEqual(result[0]["text"], "Bonjour")
            self.assertEqual(result[1]["text"], "World")  # Unchanged
            self.assertEqual(result[2]["text"], "Essai")


class TestNpcDialogueFullRoundTrip(unittest.TestCase):
    """End-to-end round-trip tests: extract -> CSV -> edit -> import -> re-extract."""

    def test_full_roundtrip(self):
        """Test complete extract -> edit CSV -> import -> verify cycle."""
        data = build_npc_dialogue([
            (1, ["Original1", "Original2"]),
            (2, ["Original3"]),
        ])

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            # Step 1: Extract to CSV
            csv_path, _, _ = extract_npc_dialogue_file(
                source_path, output_dir=tmpdir
            )

            # Step 2: Modify CSV - change target for first NPC
            rows = []
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
                for row in reader:
                    rows.append(row)

            # Translate first NPC's text
            original_text = rows[0][1]
            parts = split_join_text(original_text)
            self.assertEqual(parts, ["Original1", "Original2"])

            # Build translated join text (keeping the join tags from source)
            rows[0][2] = original_text.replace("Original1", "Traduit1").replace("Original2", "Traduit2")

            edited_csv = os.path.join(tmpdir, "edited.csv")
            with open(edited_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(header)
                for row in rows:
                    writer.writerow(row)

            # Step 3: Import translations
            output_path = import_npc_dialogue_from_csv(
                edited_csv, source_path,
                output_path=os.path.join(tmpdir, "modified.bin"),
            )
            self.assertIsNotNone(output_path)

            # Step 4: Re-extract and verify
            result = extract_npc_dialogue(output_path)
            self.assertEqual(len(result), 2)
            parts = split_join_text(result[0]["text"])
            self.assertEqual(parts, ["Traduit1", "Traduit2"])
            self.assertEqual(result[1]["text"], "Original3")

    def test_roundtrip_with_compress_encrypt(self):
        """Test import with compression and encryption flags."""
        data = build_npc_dialogue([(1, ["Test"])])

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            # Extract
            csv_path, _, _ = extract_npc_dialogue_file(
                source_path, output_dir=tmpdir
            )

            # Edit CSV
            rows = []
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
                for row in reader:
                    rows.append(row)
            rows[0][2] = "Translated"

            edited_csv = os.path.join(tmpdir, "edited.csv")
            with open(edited_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(header)
                for row in rows:
                    writer.writerow(row)

            # Import with compress + encrypt
            output_path = import_npc_dialogue_from_csv(
                edited_csv, source_path,
                output_path=os.path.join(tmpdir, "modified.bin"),
                compress=True,
                encrypt=True,
            )
            self.assertIsNotNone(output_path)

            # The output should be extractable (auto-decrypt + decompress)
            result = extract_npc_dialogue(output_path)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["text"], "Translated")

    def test_no_changes_returns_none(self):
        """Test import with no translations returns None."""
        data = build_npc_dialogue([(1, ["Test"])])

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "source.bin")
            with open(source_path, "wb") as f:
                f.write(data)

            # Extract (source == target, so no changes)
            csv_path, _, _ = extract_npc_dialogue_file(
                source_path, output_dir=tmpdir
            )

            result = import_npc_dialogue_from_csv(
                csv_path, source_path,
                output_path=os.path.join(tmpdir, "modified.bin"),
            )
            self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
