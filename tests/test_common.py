"""Tests for src/common.py — the core parsing module."""

import json
import os
import struct
import tempfile
import unittest

from src.common import (
    FTXT_HEADER_SIZE,
    FTXT_MAGIC,
    GAME_ENCODING,
    EncodingError,
    ValidationResult,
    _is_extraction_leaf,
    decode_game_string,
    encode_game_string,
    extract_ftxt,
    extract_ftxt_data,
    extract_npc_dialogue_data,
    extract_quest_file_data,
    extract_text_data_from_bytes,
    get_all_xpaths,
    is_ftxt_file,
    load_file_data,
    read_extraction_config,
    read_file_section,
    read_from_pointers,
    read_multi_pointer_entries,
    read_struct_strings,
    read_until_null,
    skip_csv_header,
    split_join_text,
    validate_file,
)
from src.binary_file import BinaryFile, InvalidPointerError
from src.crypto import encode_ecd
from src.jkr_compress import compress_jkr_hfi, compress_jkr_raw


class TestDecodeGameString(unittest.TestCase):
    """Test decode_game_string edge cases."""

    def test_ascii(self):
        self.assertEqual(decode_game_string(b"Hello"), "Hello")

    def test_empty_bytes(self):
        self.assertEqual(decode_game_string(b""), "")

    def test_shift_jis_katakana(self):
        # モンスター in Shift-JIS
        text = "モンスター"
        encoded = text.encode(GAME_ENCODING)
        self.assertEqual(decode_game_string(encoded), text)

    def test_invalid_bytes_replace_mode(self):
        # 0x80 is not a valid Shift-JIS lead byte by itself
        result = decode_game_string(b"\x80", errors="replace")
        self.assertIn("\ufffd", result)

    def test_invalid_bytes_strict_mode(self):
        with self.assertRaises(EncodingError):
            decode_game_string(b"\x80", errors="strict")

    def test_context_in_error_message(self):
        try:
            decode_game_string(b"\x80", errors="strict", context="offset 0x100")
        except EncodingError as e:
            self.assertIn("offset 0x100", str(e))

    def test_mixed_ascii_and_japanese(self):
        text = "HR999 ハンター"
        encoded = text.encode(GAME_ENCODING)
        self.assertEqual(decode_game_string(encoded), text)

    def test_null_bytes_not_stripped(self):
        # Null bytes within the data are kept (read_until_null handles termination)
        result = decode_game_string(b"A\x00B")
        self.assertEqual(result, "A\x00B")


class TestEncodeGameString(unittest.TestCase):
    """Test encode_game_string edge cases."""

    def test_ascii(self):
        self.assertEqual(encode_game_string("Hello"), b"Hello")

    def test_empty_string(self):
        self.assertEqual(encode_game_string(""), b"")

    def test_japanese_roundtrip(self):
        text = "リオレウス"
        encoded = encode_game_string(text)
        decoded = decode_game_string(encoded)
        self.assertEqual(decoded, text)

    def test_unencodable_strict(self):
        # Emoji can't be encoded in Shift-JIS
        with self.assertRaises(EncodingError):
            encode_game_string("\U0001f600", errors="strict")

    def test_unencodable_replace(self):
        result = encode_game_string("\U0001f600", errors="replace")
        self.assertIsInstance(result, bytes)

    def test_context_in_error_message(self):
        try:
            encode_game_string("\U0001f600", errors="strict", context="test entry")
        except EncodingError as e:
            self.assertIn("test entry", str(e))


class TestSplitJoinText(unittest.TestCase):
    """Test split_join_text round-trips."""

    def test_no_join_tags(self):
        self.assertEqual(split_join_text("simple text"), ["simple text"])

    def test_single_join(self):
        text = 'first<join at="100">second'
        parts = split_join_text(text)
        self.assertEqual(parts, ["first", "second"])

    def test_multiple_joins(self):
        text = 'a<join at="10">b<join at="20">c<join at="30">d'
        parts = split_join_text(text)
        self.assertEqual(parts, ["a", "b", "c", "d"])

    def test_empty_string(self):
        self.assertEqual(split_join_text(""), [""])

    def test_empty_parts_around_join(self):
        text = '<join at="10">second'
        parts = split_join_text(text)
        self.assertEqual(parts, ["", "second"])


class TestReadUntilNull(unittest.TestCase):
    """Test read_until_null."""

    def test_basic(self):
        bfile = BinaryFile.from_bytes(b"Hello\x00World")
        result = read_until_null(bfile)
        self.assertEqual(result, b"Hello")

    def test_empty_string(self):
        bfile = BinaryFile.from_bytes(b"\x00Rest")
        result = read_until_null(bfile)
        self.assertEqual(result, b"")

    def test_no_null_terminator(self):
        bfile = BinaryFile.from_bytes(b"NoNull")
        result = read_until_null(bfile)
        self.assertEqual(result, b"NoNull")

    def test_only_null(self):
        bfile = BinaryFile.from_bytes(b"\x00")
        result = read_until_null(bfile)
        self.assertEqual(result, b"")


class TestSkipCsvHeader(unittest.TestCase):
    """Test skip_csv_header."""

    def test_normal_iterator(self):
        rows = iter([["header1", "header2"], ["data1", "data2"]])
        skip_csv_header(rows, "test.csv")
        self.assertEqual(next(rows), ["data1", "data2"])

    def test_empty_iterator(self):
        rows = iter([])
        with self.assertRaises(InterruptedError):
            skip_csv_header(rows, "test.csv")


class TestIsExtractionLeaf(unittest.TestCase):
    """Test _is_extraction_leaf detection."""

    def test_standard_pointer_pair(self):
        node = {"begin_pointer": "0x10", "next_field_pointer": "0x14"}
        self.assertTrue(_is_extraction_leaf(node))

    def test_count_based(self):
        node = {"begin_pointer": "0x10", "count_pointer": "0x14"}
        self.assertTrue(_is_extraction_leaf(node))

    def test_null_terminated(self):
        node = {"begin_pointer": "0x10", "null_terminated": True}
        self.assertTrue(_is_extraction_leaf(node))

    def test_quest_table(self):
        node = {"begin_pointer": "0x10", "quest_table": True}
        self.assertTrue(_is_extraction_leaf(node))

    def test_entry_count(self):
        node = {"begin_pointer": "0x10", "entry_count": 5, "entry_size": 12, "field_offset": 4}
        self.assertTrue(_is_extraction_leaf(node))

    def test_count_base_pointer(self):
        node = {"begin_pointer": "0x10", "count_base_pointer": "0x14", "count_offset": "0x0"}
        self.assertTrue(_is_extraction_leaf(node))

    def test_no_begin_pointer(self):
        node = {"next_field_pointer": "0x14"}
        self.assertFalse(_is_extraction_leaf(node))

    def test_intermediate_node(self):
        node = {"head": {"begin_pointer": "0x10", "next_field_pointer": "0x14"}}
        self.assertFalse(_is_extraction_leaf(node))


class TestReadFileSection(unittest.TestCase):
    """Test read_file_section with synthetic binary data."""

    def _build_pointer_table(self, strings: list[str]) -> bytes:
        """Build a binary with a pointer table pointing to null-terminated strings."""
        num_ptrs = len(strings)
        table_size = num_ptrs * 4
        # Strings start right after the pointer table
        encoded = []
        offsets = []
        current_offset = table_size
        for s in strings:
            offsets.append(current_offset)
            enc = s.encode(GAME_ENCODING) + b"\x00"
            encoded.append(enc)
            current_offset += len(enc)

        data = bytearray()
        for off in offsets:
            data.extend(struct.pack("<I", off))
        for enc in encoded:
            data.extend(enc)
        return bytes(data)

    def test_basic_extraction(self):
        data = self._build_pointer_table(["Hello", "World"])
        bfile = BinaryFile.from_bytes(data)
        results = read_file_section(bfile, 0, 8)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["text"], "Hello")
        self.assertEqual(results[1]["text"], "World")

    def test_single_string(self):
        data = self._build_pointer_table(["Only"])
        bfile = BinaryFile.from_bytes(data)
        results = read_file_section(bfile, 0, 4)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["text"], "Only")

    def test_zero_length(self):
        bfile = BinaryFile.from_bytes(b"\x00" * 16)
        results = read_file_section(bfile, 0, 0)
        self.assertEqual(results, [])

    def test_join_lines_with_null_pointers(self):
        """Null pointers act as group separators; consecutive non-null pointers
        between separators are joined within the same group."""
        # Layout: [ptr_to_A, ptr_to_B, 0, ptr_to_C]
        # A and B share group 0, null increments to group 1, C is group 1
        str_a = "First".encode(GAME_ENCODING) + b"\x00"
        str_b = "Second".encode(GAME_ENCODING) + b"\x00"
        str_c = "Third".encode(GAME_ENCODING) + b"\x00"
        strings_start = 16  # 4 pointers × 4 bytes
        data = bytearray()
        data.extend(struct.pack("<I", strings_start))
        data.extend(struct.pack("<I", strings_start + len(str_a)))
        data.extend(struct.pack("<I", 0))
        data.extend(struct.pack("<I", strings_start + len(str_a) + len(str_b)))
        data.extend(str_a)
        data.extend(str_b)
        data.extend(str_c)

        bfile = BinaryFile.from_bytes(bytes(data))
        results = read_file_section(bfile, 0, 16)
        # Group 0: First + Second (joined), Group 1: Third
        self.assertEqual(len(results), 2)
        self.assertIn("First", results[0]["text"])
        self.assertIn("Second", results[0]["text"])
        self.assertIn("<join", results[0]["text"])
        self.assertEqual(results[1]["text"], "Third")

    def test_out_of_bounds_pointer(self):
        data = struct.pack("<I", 0xFFFFFF) + b"\x00" * 4
        bfile = BinaryFile.from_bytes(bytes(data))
        with self.assertRaises(InvalidPointerError):
            read_file_section(bfile, 0, 4)


class TestReadMultiPointerEntries(unittest.TestCase):
    """Test read_multi_pointer_entries."""

    def test_single_entry_single_pointer(self):
        # One entry with 1 pointer, then null terminator
        string = "Test".encode(GAME_ENCODING) + b"\x00"
        strings_start = 8  # 1 entry (4B) + terminator (4B)
        data = bytearray()
        data.extend(struct.pack("<I", strings_start))  # entry pointer
        data.extend(struct.pack("<I", 0))               # terminator
        data.extend(string)

        bfile = BinaryFile.from_bytes(bytes(data))
        results = read_multi_pointer_entries(bfile, 0, 1)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["text"], "Test")

    def test_two_pointers_per_entry(self):
        # One entry with 2 pointers, then null terminator
        str_a = "Name".encode(GAME_ENCODING) + b"\x00"
        str_b = "Desc".encode(GAME_ENCODING) + b"\x00"
        strings_start = 16  # 1 entry (8B) + terminator (8B)
        data = bytearray()
        data.extend(struct.pack("<I", strings_start))
        data.extend(struct.pack("<I", strings_start + len(str_a)))
        # Terminator: first pointer = 0
        data.extend(struct.pack("<I", 0))
        data.extend(struct.pack("<I", 0))
        data.extend(str_a)
        data.extend(str_b)

        bfile = BinaryFile.from_bytes(bytes(data))
        results = read_multi_pointer_entries(bfile, 0, 2)
        self.assertEqual(len(results), 1)
        self.assertIn("Name", results[0]["text"])
        self.assertIn("<join", results[0]["text"])
        self.assertIn("Desc", results[0]["text"])

    def test_empty_table(self):
        # Immediate null terminator
        data = struct.pack("<I", 0)
        bfile = BinaryFile.from_bytes(data)
        results = read_multi_pointer_entries(bfile, 0, 1)
        self.assertEqual(results, [])


class TestReadStructStrings(unittest.TestCase):
    """Test read_struct_strings."""

    def test_basic(self):
        # 2 structs of 8 bytes each, string pointer at offset 4
        str_a = "Alpha".encode(GAME_ENCODING) + b"\x00"
        str_b = "Beta".encode(GAME_ENCODING) + b"\x00"
        strings_start = 16  # 2 structs × 8 bytes
        data = bytearray()
        # Struct 0: [padding(4), ptr_to_a(4)]
        data.extend(b"\x00\x00\x00\x00")
        data.extend(struct.pack("<I", strings_start))
        # Struct 1: [padding(4), ptr_to_b(4)]
        data.extend(b"\x00\x00\x00\x00")
        data.extend(struct.pack("<I", strings_start + len(str_a)))
        data.extend(str_a)
        data.extend(str_b)

        bfile = BinaryFile.from_bytes(bytes(data))
        results = read_struct_strings(bfile, 0, 2, 8, 4)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["text"], "Alpha")
        self.assertEqual(results[1]["text"], "Beta")

    def test_null_pointer_skipped(self):
        # Struct with null pointer is skipped
        data = bytearray()
        data.extend(struct.pack("<I", 0))  # null ptr
        bfile = BinaryFile.from_bytes(bytes(data))
        results = read_struct_strings(bfile, 0, 1, 4, 0)
        self.assertEqual(results, [])


class TestIsFtxtFile(unittest.TestCase):
    """Test is_ftxt_file detection."""

    def test_valid_ftxt(self):
        data = struct.pack("<I", FTXT_MAGIC) + b"\x00" * 12
        self.assertTrue(is_ftxt_file(data))

    def test_not_ftxt(self):
        self.assertFalse(is_ftxt_file(b"\x00\x00\x00\x00"))

    def test_too_short(self):
        self.assertFalse(is_ftxt_file(b"\x00\x0b"))

    def test_empty(self):
        self.assertFalse(is_ftxt_file(b""))


class TestExtractFtxtData(unittest.TestCase):
    """Test extract_ftxt_data."""

    def _build_ftxt(self, strings: list[str]) -> bytes:
        """Build a minimal FTXT binary."""
        text_parts = []
        for s in strings:
            text_parts.append(s.encode(GAME_ENCODING) + b"\x00")
        text_block = b"".join(text_parts)
        header = struct.pack("<I6xHI", FTXT_MAGIC, len(strings), len(text_block))
        return header + text_block

    def test_basic_extraction(self):
        data = self._build_ftxt(["Hello", "World"])
        results = extract_ftxt_data(data)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["text"], "Hello")
        self.assertEqual(results[1]["text"], "World")

    def test_single_string(self):
        data = self._build_ftxt(["Only"])
        results = extract_ftxt_data(data)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["text"], "Only")

    def test_empty_strings(self):
        data = self._build_ftxt(["", ""])
        results = extract_ftxt_data(data)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["text"], "")
        self.assertEqual(results[1]["text"], "")

    def test_not_ftxt(self):
        with self.assertRaises(ValueError):
            extract_ftxt_data(b"\x00\x00\x00\x00" + b"\x00" * 12)

    def test_truncated_header(self):
        data = struct.pack("<I", FTXT_MAGIC)  # only 4 bytes
        with self.assertRaises(ValueError):
            extract_ftxt_data(data)

    def test_japanese_strings(self):
        data = self._build_ftxt(["狩猟", "モンスター"])
        results = extract_ftxt_data(data)
        self.assertEqual(results[0]["text"], "狩猟")
        self.assertEqual(results[1]["text"], "モンスター")


class TestExtractQuestFileData(unittest.TestCase):
    """Test extract_quest_file_data."""

    def _build_quest(self, strings: list[str]) -> bytes:
        """Build a minimal quest binary with text pointers."""
        # Layout:
        # @0x00: questTypeFlagsPtr → points to quest props block
        # Quest props block at some offset, QuestStringsPtr at +0xE8
        # QuestText block: 8 string pointers (padded) followed by strings
        quest_props_offset = 0x100
        strings_block_offset = quest_props_offset + 0xEC
        # Always 8 pointers in the text block (standard quest format)
        text_pointers_count = 8

        # Build string data
        encoded = []
        str_offsets = []
        current = strings_block_offset + text_pointers_count * 4
        for s in strings:
            str_offsets.append(current)
            enc = s.encode(GAME_ENCODING) + b"\x00"
            encoded.append(enc)
            current += len(enc)

        data = bytearray(current)
        # Header: questTypeFlagsPtr
        struct.pack_into("<I", data, 0, quest_props_offset)
        # Quest props: QuestStringsPtr at +0xE8
        struct.pack_into("<I", data, quest_props_offset + 0xE8, strings_block_offset)
        # String pointers (fill used slots, rest are 0)
        for i, off in enumerate(str_offsets):
            struct.pack_into("<I", data, strings_block_offset + i * 4, off)
        # Strings
        for i, enc in enumerate(encoded):
            off = str_offsets[i]
            data[off:off + len(enc)] = enc

        return bytes(data)

    def test_basic_extraction(self):
        data = self._build_quest(["Quest Title", "Main Text"])
        results = extract_quest_file_data(data)
        self.assertEqual(len(results), 1)  # grouped into one entry
        self.assertIn("Quest Title", results[0]["text"])
        self.assertIn("Main Text", results[0]["text"])

    def test_null_quest_type_flags(self):
        data = b"\x00" * 256
        results = extract_quest_file_data(data)
        self.assertEqual(results, [])

    def test_null_strings_ptr(self):
        data = bytearray(0x200)
        struct.pack_into("<I", data, 0, 0x100)
        # Leave QuestStringsPtr at 0
        results = extract_quest_file_data(bytes(data))
        self.assertEqual(results, [])


class TestExtractNpcDialogueData(unittest.TestCase):
    """Test extract_npc_dialogue_data."""

    def test_too_short(self):
        self.assertEqual(extract_npc_dialogue_data(b"\x00"), [])

    def test_empty_npc_table(self):
        # Immediate terminator
        data = struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF)
        results = extract_npc_dialogue_data(data)
        self.assertEqual(results, [])


class TestExtractTextDataFromBytes(unittest.TestCase):
    """Test extract_text_data_from_bytes with various config modes."""

    def _build_standard_binary(self, strings: list[str]) -> tuple[bytes, dict]:
        """Build binary with standard pointer-pair config."""
        # File layout:
        # @0x00: pointer to start of pointer table (header)
        # @0x04: pointer to end of pointer table (next_field)
        # @0x08: start of pointer table
        # After table: strings
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
        # Header pointers (point to table start and end)
        data.extend(struct.pack("<I", table_start))
        data.extend(struct.pack("<I", table_start + table_size))
        # Pointer table
        for off in offsets:
            data.extend(struct.pack("<I", off))
        # Strings
        for enc in encoded:
            data.extend(enc)

        config = {
            "begin_pointer": "0x0",
            "next_field_pointer": "0x4",
        }
        return bytes(data), config

    def test_standard_pointer_pair(self):
        data, config = self._build_standard_binary(["Sword", "Shield"])
        results = extract_text_data_from_bytes(data, config)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["text"], "Sword")
        self.assertEqual(results[1]["text"], "Shield")

    def test_standard_with_crop_end(self):
        data, config = self._build_standard_binary(["A", "B", "C"])
        config["crop_end"] = 4  # Crop last pointer
        results = extract_text_data_from_bytes(data, config)
        self.assertEqual(len(results), 2)

    def test_count_based(self):
        """Count-based pointer table."""
        # @0x00: ptr to table start
        # @0x04: count (2)
        # @0x08: pointer table
        strings = ["One", "Two"]
        header_size = 8
        table_start = header_size
        strings_start = header_size + len(strings) * 4

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
        data.extend(struct.pack("<I", len(strings)))
        for off in offsets:
            data.extend(struct.pack("<I", off))
        for enc in encoded:
            data.extend(enc)

        config = {
            "begin_pointer": "0x0",
            "count_pointer": "0x4",
        }
        results = extract_text_data_from_bytes(bytes(data), config)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["text"], "One")
        self.assertEqual(results[1]["text"], "Two")

    def test_count_based_zero_count(self):
        data = struct.pack("<II", 8, 0)
        config = {"begin_pointer": "0x0", "count_pointer": "0x4"}
        results = extract_text_data_from_bytes(bytes(data), config)
        self.assertEqual(results, [])

    def test_null_terminated(self):
        """Null-terminated mode."""
        # @0x00: ptr to table start
        # @0x04: pointer table with null terminator
        str_a = "Alpha".encode(GAME_ENCODING) + b"\x00"
        table_start = 4
        strings_start = table_start + 8  # 1 pointer + null terminator
        data = bytearray()
        data.extend(struct.pack("<I", table_start))
        data.extend(struct.pack("<I", strings_start))
        data.extend(struct.pack("<I", 0))  # null terminator
        data.extend(str_a)

        config = {
            "begin_pointer": "0x0",
            "null_terminated": True,
        }
        results = extract_text_data_from_bytes(bytes(data), config)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["text"], "Alpha")

    def test_struct_strided(self):
        """Struct-strided with entry_count."""
        # @0x00: ptr to struct array
        # Struct array: 2 entries × 8 bytes, string ptr at offset 4
        str_a = "Cat".encode(GAME_ENCODING) + b"\x00"
        str_b = "Dog".encode(GAME_ENCODING) + b"\x00"
        array_start = 4
        strings_start = array_start + 16
        data = bytearray()
        data.extend(struct.pack("<I", array_start))
        # Struct 0
        data.extend(b"\x00\x00\x00\x00")
        data.extend(struct.pack("<I", strings_start))
        # Struct 1
        data.extend(b"\x00\x00\x00\x00")
        data.extend(struct.pack("<I", strings_start + len(str_a)))
        data.extend(str_a)
        data.extend(str_b)

        config = {
            "begin_pointer": "0x0",
            "entry_count": 2,
            "entry_size": 8,
            "field_offset": 4,
        }
        results = extract_text_data_from_bytes(bytes(data), config)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["text"], "Cat")
        self.assertEqual(results[1]["text"], "Dog")

    def test_unknown_config_raises(self):
        config = {"begin_pointer": "0x0"}
        data = struct.pack("<I", 0)
        with self.assertRaises(ValueError) as ctx:
            extract_text_data_from_bytes(data, config)
        self.assertIn("Unknown extraction config", str(ctx.exception))


class TestLoadFileData(unittest.TestCase):
    """Test load_file_data with encryption and compression."""

    def _write_temp(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.write(fd, data)
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_plain_file(self):
        data = b"plain data here"
        path = self._write_temp(data)
        result = load_file_data(path)
        self.assertEqual(result, data)

    def test_encrypted_file(self):
        plain = b"\x00" * 64
        encrypted = encode_ecd(plain, key_index=4)
        path = self._write_temp(encrypted)
        result = load_file_data(path)
        self.assertEqual(result, plain)

    def test_compressed_file(self):
        plain = b"Test data for compression " * 10
        compressed = compress_jkr_raw(plain)
        path = self._write_temp(compressed)
        result = load_file_data(path)
        self.assertEqual(result, plain)

    def test_encrypted_then_compressed(self):
        plain = b"\x00" * 128
        compressed = compress_jkr_raw(plain)
        encrypted = encode_ecd(compressed, key_index=4)
        path = self._write_temp(encrypted)
        result = load_file_data(path)
        self.assertEqual(result, plain)


class TestReadFromPointers(unittest.TestCase):
    """Test read_from_pointers with file I/O."""

    def _write_temp(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.write(fd, data)
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_basic(self):
        # Build a binary: header → pointer table → strings
        strings = ["Hello", "World"]
        header_size = 8
        table_start = header_size
        table_size = len(strings) * 4
        strings_start = table_start + table_size

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

        path = self._write_temp(bytes(data))
        results = read_from_pointers(path, (0, 4, 0))
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["text"], "Hello")
        self.assertEqual(results[1]["text"], "World")


class TestGetAllXpaths(unittest.TestCase):
    """Test get_all_xpaths from headers.json."""

    def test_returns_sorted_list(self):
        headers = {
            "dat": {
                "armors": {
                    "head": {"begin_pointer": "0x10", "next_field_pointer": "0x14"},
                    "body": {"begin_pointer": "0x18", "next_field_pointer": "0x1C"},
                }
            }
        }
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(headers, f)
        self.addCleanup(os.unlink, path)

        xpaths = get_all_xpaths(path)
        self.assertEqual(xpaths, ["dat/armors/body", "dat/armors/head"])

    def test_skips_comment_fields(self):
        headers = {
            "dat": {
                "_comment": "This is a comment",
                "items": {"begin_pointer": "0x10", "next_field_pointer": "0x14"},
            }
        }
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(headers, f)
        self.addCleanup(os.unlink, path)

        xpaths = get_all_xpaths(path)
        self.assertEqual(xpaths, ["dat/items"])


class TestReadExtractionConfig(unittest.TestCase):
    """Test read_extraction_config."""

    def setUp(self):
        self.headers = {
            "dat": {
                "armors": {
                    "head": {"begin_pointer": "0x10", "next_field_pointer": "0x14"},
                }
            }
        }
        fd, self.path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(self.headers, f)
        self.addCleanup(os.unlink, self.path)

    def test_valid_xpath(self):
        config = read_extraction_config("dat/armors/head", self.path)
        self.assertEqual(config["begin_pointer"], "0x10")

    def test_invalid_xpath_intermediate(self):
        with self.assertRaises(ValueError):
            read_extraction_config("dat/armors", self.path)

    def test_nonexistent_xpath(self):
        with self.assertRaises(KeyError):
            read_extraction_config("dat/weapons/sword", self.path)


class TestValidateFile(unittest.TestCase):
    """Test validate_file (supplementary to test_validate.py)."""

    def _write_temp(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.write(fd, data)
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_result_fields(self):
        result = ValidationResult(
            file_path="x.bin", file_size=10, valid=True
        )
        self.assertEqual(result.layers, [])
        self.assertEqual(result.inner_format, "Raw binary data")
        self.assertIsNone(result.error)

    def test_ftxt_detection(self):
        strings = [b"A\x00", b"B\x00"]
        text_block = b"".join(strings)
        header = struct.pack("<I6xHI", FTXT_MAGIC, 2, len(text_block))
        data = header + text_block
        path = self._write_temp(data)
        result = validate_file(path)
        self.assertTrue(result.valid)
        self.assertIn("FTXT", result.inner_format)


class TestExtractFtxt(unittest.TestCase):
    """Test extract_ftxt with file I/O."""

    def _write_temp(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.write(fd, data)
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def _build_ftxt(self, strings: list[str]) -> bytes:
        text_parts = []
        for s in strings:
            text_parts.append(s.encode(GAME_ENCODING) + b"\x00")
        text_block = b"".join(text_parts)
        header = struct.pack("<I6xHI", FTXT_MAGIC, len(strings), len(text_block))
        return header + text_block

    def test_extract_from_file(self):
        data = self._build_ftxt(["Test"])
        path = self._write_temp(data)
        results = extract_ftxt(path)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["text"], "Test")

    def test_not_ftxt_raises(self):
        path = self._write_temp(b"\x00" * 20)
        with self.assertRaises(ValueError):
            extract_ftxt(path)

    def test_encrypted_ftxt(self):
        data = self._build_ftxt(["Encrypted"])
        encrypted = encode_ecd(data, key_index=4)
        path = self._write_temp(encrypted)
        results = extract_ftxt(path)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["text"], "Encrypted")


if __name__ == "__main__":
    unittest.main()
