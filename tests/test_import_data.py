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


class TestApplyTranslationsFromReleaseJson(unittest.TestCase):
    """Test apply_translations_from_release_json — the full JSON→game-file chain."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmpdir))

    def _build_game_binary(self, strings: list[str]) -> bytes:
        """Build a minimal pointer-table binary.

        Layout:
          [begin_ptr 4B][next_ptr 4B]  ← two pointers forming the header
          [ptr0 4B][ptr1 4B]…           ← pointer table (one per string)
          [str0\0][str1\0]…             ← null-terminated Shift-JIS strings

        begin_ptr points to the start of the pointer table (offset 8).
        next_ptr points to the first byte after the pointer table.
        Each ptrN points to its string.
        """
        header_size = 8
        table_size = len(strings) * 4
        table_start = header_size
        strings_start = header_size + table_size

        encoded = []
        offsets = []
        pos = strings_start
        for s in strings:
            offsets.append(pos)
            enc = s.encode(GAME_ENCODING) + b"\x00"
            encoded.append(enc)
            pos += len(enc)

        data = bytearray()
        # Header: pointers to table boundaries
        data.extend(struct.pack("<I", table_start))
        data.extend(struct.pack("<I", strings_start))
        # Pointer table
        for off in offsets:
            data.extend(struct.pack("<I", off))
        # Strings
        for enc in encoded:
            data.extend(enc)
        return bytes(data)

    def _write_release_json(self, lang: str, sections: dict) -> str:
        """Write a release-format JSON and return the path.

        sections: {xpath: [(ptr_offset, source, target)]}
        """
        data = {}
        for xpath, entries in sections.items():
            data.setdefault(lang, {})[xpath] = [
                {
                    "location": f"0x{ptr_off:x}@game.bin",
                    "source": src,
                    "target": tgt,
                }
                for ptr_off, src, tgt in entries
            ]
        path = os.path.join(self.tmpdir, "translations-translated.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        return path

    def test_apply_plain_binary(self):
        """Apply translations to an unencrypted, uncompressed game binary."""
        from src.import_data import apply_translations_from_release_json

        original_strings = ["Helmet", "Sword", "Shield"]
        raw = self._build_game_binary(original_strings)

        # Place the binary in a fake game directory at dat/mhfdat.bin
        game_dir = os.path.join(self.tmpdir, "game")
        dat_dir = os.path.join(game_dir, "dat")
        os.makedirs(dat_dir)
        bin_path = os.path.join(dat_dir, "mhfdat.bin")
        with open(bin_path, "wb") as f:
            f.write(raw)

        # Pointer table starts at offset 8.  First pointer is at 8, second at 12.
        json_path = self._write_release_json("fr", {
            "dat/armors/head": [
                (8, "Helmet", "Casque"),
                (12, "Sword", "Epée"),
            ],
        })

        results = apply_translations_from_release_json(
            json_path, lang="fr", game_dir=game_dir,
            compress=False, encrypt=False,
        )

        self.assertIn(os.path.join("dat", "mhfdat.bin"), results)
        self.assertEqual(results[os.path.join("dat", "mhfdat.bin")], 2)

        # Read back and verify the pointers now reference the translated strings
        with open(bin_path, "rb") as f:
            patched = f.read()

        bfile = BinaryFile.from_bytes(patched)
        for ptr_off, expected in [(8, "Casque"), (12, "Epée")]:
            bfile.seek(ptr_off)
            str_off = struct.unpack("<I", bfile.read(4))[0]
            bfile.seek(str_off)
            raw_bytes = bytearray()
            b = bfile.read(1)
            while b != b"\x00" and b != b"":
                raw_bytes.extend(b)
                b = bfile.read(1)
            self.assertEqual(raw_bytes.decode(GAME_ENCODING), expected)

        # Third pointer (offset 16) should still point to the original "Shield"
        bfile.seek(16)
        str_off = struct.unpack("<I", bfile.read(4))[0]
        bfile.seek(str_off)
        raw_bytes = bytearray()
        b = bfile.read(1)
        while b != b"\x00" and b != b"":
            raw_bytes.extend(b)
            b = bfile.read(1)
        self.assertEqual(raw_bytes.decode(GAME_ENCODING), "Shield")

    def test_apply_encrypted_compressed_roundtrip(self):
        """Apply translations to an encrypted+compressed binary and verify."""
        from src.import_data import apply_translations_from_release_json
        from src.jkr_compress import compress_jkr_hfi
        from src.jkr_decompress import decompress_jkr, is_jkr_file
        from src.crypto import encode_ecd, is_encrypted_file, decrypt

        raw = self._build_game_binary(["Alpha", "Beta"])
        # Wrap in compression + encryption (as found in the real game)
        compressed = compress_jkr_hfi(raw)
        encrypted = encode_ecd(compressed)

        game_dir = os.path.join(self.tmpdir, "game")
        dat_dir = os.path.join(game_dir, "dat")
        os.makedirs(dat_dir)
        bin_path = os.path.join(dat_dir, "mhfdat.bin")
        with open(bin_path, "wb") as f:
            f.write(encrypted)

        json_path = self._write_release_json("fr", {
            "dat/test_section": [(8, "Alpha", "Un")],
        })

        results = apply_translations_from_release_json(
            json_path, lang="fr", game_dir=game_dir,
            compress=True, encrypt=True,
        )
        self.assertEqual(results[os.path.join("dat", "mhfdat.bin")], 1)

        # The output file should be encrypted and compressed again
        with open(bin_path, "rb") as f:
            output = f.read()

        self.assertTrue(is_encrypted_file(output))
        decrypted, _ = decrypt(output)
        self.assertTrue(is_jkr_file(decrypted))
        decompressed = decompress_jkr(decrypted)

        # Verify the translated string is present
        bfile = BinaryFile.from_bytes(decompressed)
        bfile.seek(8)
        str_off = struct.unpack("<I", bfile.read(4))[0]
        bfile.seek(str_off)
        raw_bytes = bytearray()
        b = bfile.read(1)
        while b != b"\x00" and b != b"":
            raw_bytes.extend(b)
            b = bfile.read(1)
        self.assertEqual(raw_bytes.decode(GAME_ENCODING), "Un")

    def test_apply_rewrites_color_codes(self):
        """Release-JSON targets in {cNN}/{/c} brace form land in the binary as ‾CNN bytes.

        Regression: before this was wired up, apply_translations_from_release_json
        skipped color_codes_from_csv and wrote ``{c05}foo{/c}`` verbatim into the
        binary, so the game would render the braces as text instead of colouring.
        """
        from src.import_data import apply_translations_from_release_json

        raw = self._build_game_binary(["PlainOriginal"])
        game_dir = os.path.join(self.tmpdir, "game")
        dat_dir = os.path.join(game_dir, "dat")
        os.makedirs(dat_dir)
        bin_path = os.path.join(dat_dir, "mhfdat.bin")
        with open(bin_path, "wb") as f:
            f.write(raw)

        # Pointer table starts at offset 8; one pointer for the single string.
        json_path = self._write_release_json("fr", {
            "dat/armors/head": [
                (8, "PlainOriginal", "{c05}Colored{/c} text"),
            ],
        })

        results = apply_translations_from_release_json(
            json_path, lang="fr", game_dir=game_dir,
            compress=False, encrypt=False,
        )
        self.assertEqual(results[os.path.join("dat", "mhfdat.bin")], 1)

        with open(bin_path, "rb") as f:
            patched = f.read()

        bfile = BinaryFile.from_bytes(patched)
        bfile.seek(8)
        str_off = struct.unpack("<I", bfile.read(4))[0]
        bfile.seek(str_off)
        raw_bytes = bytearray()
        b = bfile.read(1)
        while b != b"\x00" and b != b"":
            raw_bytes.extend(b)
            b = bfile.read(1)

        decoded = raw_bytes.decode(GAME_ENCODING)
        # The game form uses ‾ (U+203E) because 0x7E decodes that way in
        # shift_jisx0213. The brace form must not survive into the binary.
        self.assertEqual(decoded, "\u203eC05Colored\u203eC00 text")
        self.assertNotIn("{c05}", decoded)
        self.assertNotIn("{/c}", decoded)

    def test_apply_rewrites_color_codes_indexed(self):
        """Same regression check for index-keyed release entries."""
        from src.import_data import apply_translations_from_release_json

        raw = self._build_game_binary(["Original"])
        game_dir = os.path.join(self.tmpdir, "game")
        dat_dir = os.path.join(game_dir, "dat")
        os.makedirs(dat_dir)
        bin_path = os.path.join(dat_dir, "mhfdat.bin")
        with open(bin_path, "wb") as f:
            f.write(raw)

        # Index-keyed entry: the xpath must exist in headers.json for the
        # index→offset resolver to kick in. Use a real section with a single
        # entry in our synthetic binary — we override via a custom headers.
        headers_path = os.path.join(self.tmpdir, "headers.json")
        with open(headers_path, "w") as f:
            json.dump({
                "dat": {
                    "armors": {
                        "head": {
                            "begin_pointer": "0x0",
                            "next_field_pointer": "0x4",
                        }
                    }
                }
            }, f)

        data = {
            "fr": {
                "dat/armors/head": [
                    {
                        "index": 0,
                        "source": "Original",
                        "target": "{c14}Rouge{/c}",
                    }
                ]
            }
        }
        json_path = os.path.join(self.tmpdir, "translations-translated.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)

        results = apply_translations_from_release_json(
            json_path, lang="fr", game_dir=game_dir,
            compress=False, encrypt=False,
            headers_path=headers_path,
        )
        self.assertEqual(results[os.path.join("dat", "mhfdat.bin")], 1)

        with open(bin_path, "rb") as f:
            patched = f.read()
        bfile = BinaryFile.from_bytes(patched)
        bfile.seek(8)
        str_off = struct.unpack("<I", bfile.read(4))[0]
        bfile.seek(str_off)
        raw_bytes = bytearray()
        b = bfile.read(1)
        while b != b"\x00" and b != b"":
            raw_bytes.extend(b)
            b = bfile.read(1)
        decoded = raw_bytes.decode(GAME_ENCODING)
        self.assertEqual(decoded, "\u203eC14Rouge\u203eC00")
        self.assertNotIn("{c14}", decoded)

    def _build_grouped_binary(self) -> bytes:
        """Build a binary with one grouped entry (2 sub-pointers) + 1 single.

        Layout:
          0x00-0x07: header (begin_ptr, next_ptr)
          0x08-0x17: pointer table — [ptr0, ptr1, 0, ptr2]
          0x18+   : strings "Hello\\0", "World\\0", "Bye\\0"

        The 0-separator at 0x10 splits the grouped entry (ptr0+ptr1,
        both pointing into the grouped row) from the standalone ptr2.
        """
        header_size = 8
        strings_start = header_size + 4 * 4  # 0x18
        table = [
            strings_start,       # ptr0 → "Hello"
            strings_start + 6,   # ptr1 → "World" (after "Hello\0")
            0,                   # group separator
            strings_start + 12,  # ptr2 → "Bye"   (after "Hello\0World\0")
        ]
        table_bytes = b"".join(struct.pack("<I", p) for p in table)
        strings = b"Hello\x00World\x00Bye\x00"
        header = (
            struct.pack("<I", header_size)
            + struct.pack("<I", header_size + len(table_bytes))
        )
        return header + table_bytes + strings

    def test_apply_grouped_entry_with_new_j_marker(self):
        """A grouped translation using the 1.6.0 ``{j}`` marker in the
        release JSON must land with BOTH sibling pointers updated.

        Before the format change the legacy path wrote the text verbatim
        with the literal marker, leaving the second pointer stale and
        visibly broken in-game. This regression test locks in the fix.
        """
        from src.import_data import apply_translations_from_release_json

        raw = self._build_grouped_binary()
        game_dir = os.path.join(self.tmpdir, "game")
        dat_dir = os.path.join(game_dir, "dat")
        os.makedirs(dat_dir)
        bin_path = os.path.join(dat_dir, "mhfdat.bin")
        with open(bin_path, "wb") as f:
            f.write(raw)

        # Custom headers.json pointing at our section. The section uses
        # multi-pointer mode with 2 pointers per entry and a null-
        # terminator group separator — same shape as the real inf/quests
        # section, minus the scale.
        headers_path = os.path.join(self.tmpdir, "headers.json")
        with open(headers_path, "w") as f:
            json.dump({
                "dat": {
                    "armors": {
                        "head": {
                            "begin_pointer": "0x0",
                            "next_field_pointer": "0x4",
                        }
                    }
                }
            }, f)

        # Release JSON: index-keyed entry with a {j}-form target for the
        # grouped row. In 1.5.x this would have been written as
        # `<join at="...">` but post-1.6.0 it's the clean brace form.
        data = {
            "fr": {
                "dat/armors/head": [
                    {
                        "index": 0,
                        "source": "Hello{j}World",
                        "target": "Bonjour{j}Monde",
                    }
                ]
            }
        }
        json_path = os.path.join(self.tmpdir, "translations-translated.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)

        results = apply_translations_from_release_json(
            json_path, lang="fr", game_dir=game_dir,
            compress=False, encrypt=False,
            headers_path=headers_path,
        )
        self.assertEqual(results[os.path.join("dat", "mhfdat.bin")], 2)

        with open(bin_path, "rb") as f:
            patched = f.read()

        def read_str_at(ptr_slot: int) -> str:
            bfile = BinaryFile.from_bytes(patched)
            bfile.seek(ptr_slot)
            str_off = struct.unpack("<I", bfile.read(4))[0]
            bfile.seek(str_off)
            buf = bytearray()
            b = bfile.read(1)
            while b != b"\x00" and b != b"":
                buf.extend(b)
                b = bfile.read(1)
            return buf.decode(GAME_ENCODING)

        # Both grouped sub-pointers must land on the translated subs.
        self.assertEqual(read_str_at(0x8), "Bonjour")
        self.assertEqual(read_str_at(0xC), "Monde")
        # The standalone pointer at 0x14 (after the zero separator at
        # 0x10) must still point at the untouched original "Bye".
        self.assertEqual(read_str_at(0x14), "Bye")
        # And critically: the literal ``{j}`` must not have been written
        # into the binary as text.
        self.assertNotIn(b"{j}", patched)

    def test_apply_grouped_entry_with_legacy_join_tag(self):
        """Same regression check but with the pre-1.6.0 ``<join at=N>``
        form still accepted — legacy translation files must keep
        working."""
        from src.import_data import apply_translations_from_release_json

        raw = self._build_grouped_binary()
        game_dir = os.path.join(self.tmpdir, "game")
        dat_dir = os.path.join(game_dir, "dat")
        os.makedirs(dat_dir)
        bin_path = os.path.join(dat_dir, "mhfdat.bin")
        with open(bin_path, "wb") as f:
            f.write(raw)

        headers_path = os.path.join(self.tmpdir, "headers.json")
        with open(headers_path, "w") as f:
            json.dump({
                "dat": {
                    "armors": {
                        "head": {
                            "begin_pointer": "0x0",
                            "next_field_pointer": "0x4",
                        }
                    }
                }
            }, f)

        data = {
            "fr": {
                "dat/armors/head": [
                    {
                        "index": 0,
                        "source": 'Hello<join at="12">World',
                        "target": 'Bonjour<join at="12">Monde',
                    }
                ]
            }
        }
        json_path = os.path.join(self.tmpdir, "translations-translated.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)

        results = apply_translations_from_release_json(
            json_path, lang="fr", game_dir=game_dir,
            compress=False, encrypt=False,
            headers_path=headers_path,
        )
        self.assertEqual(results[os.path.join("dat", "mhfdat.bin")], 2)

        with open(bin_path, "rb") as f:
            patched = f.read()

        def read_str_at(ptr_slot: int) -> str:
            bfile = BinaryFile.from_bytes(patched)
            bfile.seek(ptr_slot)
            str_off = struct.unpack("<I", bfile.read(4))[0]
            bfile.seek(str_off)
            buf = bytearray()
            b = bfile.read(1)
            while b != b"\x00" and b != b"":
                buf.extend(b)
                b = bfile.read(1)
            return buf.decode(GAME_ENCODING)

        self.assertEqual(read_str_at(0x8), "Bonjour")
        self.assertEqual(read_str_at(0xC), "Monde")
        self.assertNotIn(b"<join", patched)

    def test_missing_language_raises(self):
        """ValueError when the requested language isn't in the JSON but others exist."""
        from src.import_data import apply_translations_from_release_json

        json_path = self._write_release_json("fr", {
            "dat/x": [(8, "a", "b")],
        })
        with self.assertRaises(ValueError) as ctx:
            apply_translations_from_release_json(
                json_path, lang="de", game_dir=self.tmpdir,
                compress=False, encrypt=False,
            )
        self.assertIn("de", str(ctx.exception))
        self.assertIn("fr", str(ctx.exception))

    def test_empty_json_returns_empty(self):
        """Empty JSON (no languages at all) returns empty results, not an error."""
        from src.import_data import apply_translations_from_release_json

        path = os.path.join(self.tmpdir, "empty.json")
        with open(path, "w") as f:
            json.dump({}, f)

        results = apply_translations_from_release_json(
            path, lang="fr", game_dir=self.tmpdir,
            compress=False, encrypt=False,
        )
        self.assertEqual(results, {})

    def test_missing_game_file_skipped(self):
        """Missing game files are skipped with a warning, not an error."""
        from src.import_data import apply_translations_from_release_json

        game_dir = os.path.join(self.tmpdir, "empty_game")
        os.makedirs(game_dir)

        json_path = self._write_release_json("fr", {
            "dat/armors/head": [(8, "a", "b")],
        })

        results = apply_translations_from_release_json(
            json_path, lang="fr", game_dir=game_dir,
            compress=False, encrypt=False,
        )
        self.assertEqual(results, {})

    def test_skips_empty_target(self):
        """Entries with empty target are not applied."""
        from src.import_data import apply_translations_from_release_json

        raw = self._build_game_binary(["Hello"])
        game_dir = os.path.join(self.tmpdir, "game")
        dat_dir = os.path.join(game_dir, "dat")
        os.makedirs(dat_dir)
        bin_path = os.path.join(dat_dir, "mhfdat.bin")
        with open(bin_path, "wb") as f:
            f.write(raw)

        json_path = self._write_release_json("fr", {
            "dat/section": [(8, "Hello", "")],
        })

        results = apply_translations_from_release_json(
            json_path, lang="fr", game_dir=game_dir,
            compress=False, encrypt=False,
        )
        self.assertEqual(results, {})

    def test_multiple_sections_same_file(self):
        """Translations from multiple xpaths targeting the same binary are merged."""
        from src.import_data import apply_translations_from_release_json

        raw = self._build_game_binary(["One", "Two", "Three"])
        game_dir = os.path.join(self.tmpdir, "game")
        dat_dir = os.path.join(game_dir, "dat")
        os.makedirs(dat_dir)
        bin_path = os.path.join(dat_dir, "mhfdat.bin")
        with open(bin_path, "wb") as f:
            f.write(raw)

        # Two different xpath sections, both targeting mhfdat.bin
        json_path = self._write_release_json("fr", {
            "dat/section_a": [(8, "One", "Un")],
            "dat/section_b": [(12, "Two", "Deux")],
        })

        results = apply_translations_from_release_json(
            json_path, lang="fr", game_dir=game_dir,
            compress=False, encrypt=False,
        )
        self.assertEqual(results[os.path.join("dat", "mhfdat.bin")], 2)


    def _write_indexed_release_json(self, lang: str, sections: dict) -> str:
        """Write a release JSON whose entries use the new ``index`` key.

        sections: {xpath: [(slot_index, source, target)]}
        """
        data = {}
        for xpath, entries in sections.items():
            data.setdefault(lang, {})[xpath] = [
                {"index": idx, "source": src, "target": tgt}
                for idx, src, tgt in entries
            ]
        path = os.path.join(self.tmpdir, "translations-indexed.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        return path

    def test_apply_index_keyed_entries(self):
        """Release JSON entries keyed by `index` are resolved against
        the section's pointer table and applied correctly."""
        from src.import_data import apply_translations_from_release_json

        raw = self._build_game_binary(["Helmet", "Sword", "Shield"])
        game_dir = os.path.join(self.tmpdir, "game")
        dat_dir = os.path.join(game_dir, "dat")
        os.makedirs(dat_dir)
        bin_path = os.path.join(dat_dir, "mhfdat.bin")
        with open(bin_path, "wb") as f:
            f.write(raw)

        # Synthetic headers.json matching the test binary's layout:
        # begin_pointer at 0 (→ table_start = 8), next_field_pointer at 4
        # (→ first byte after the 12-byte table = 20).
        headers_path = os.path.join(self.tmpdir, "headers.json")
        with open(headers_path, "w", encoding="utf-8") as f:
            json.dump({
                "dat": {
                    "armors": {
                        "head": {
                            "begin_pointer": "0x0",
                            "next_field_pointer": "0x4",
                        }
                    }
                }
            }, f)

        # Slot 0 → Helmet, slot 2 → Shield. Slot 1 untouched.
        json_path = self._write_indexed_release_json("fr", {
            "dat/armors/head": [
                (0, "Helmet", "Casque"),
                (2, "Shield", "Bouclier"),
            ],
        })

        results = apply_translations_from_release_json(
            json_path, lang="fr", game_dir=game_dir,
            compress=False, encrypt=False,
            headers_path=headers_path,
        )
        self.assertEqual(results[os.path.join("dat", "mhfdat.bin")], 2)

        # Verify pointers now reference the translations
        with open(bin_path, "rb") as f:
            patched = f.read()
        bfile = BinaryFile.from_bytes(patched)
        # Slot 0 pointer is at offset 8, slot 2 pointer at offset 16
        for ptr_off, expected in [(8, "Casque"), (16, "Bouclier")]:
            bfile.seek(ptr_off)
            str_off = struct.unpack("<I", bfile.read(4))[0]
            bfile.seek(str_off)
            buf = bytearray()
            b = bfile.read(1)
            while b not in (b"\x00", b""):
                buf.extend(b)
                b = bfile.read(1)
            self.assertEqual(buf.decode(GAME_ENCODING), expected)
        # Slot 1 (offset 12) should still resolve to "Sword"
        bfile.seek(12)
        str_off = struct.unpack("<I", bfile.read(4))[0]
        bfile.seek(str_off)
        buf = bytearray()
        b = bfile.read(1)
        while b not in (b"\x00", b""):
            buf.extend(b)
            b = bfile.read(1)
        self.assertEqual(buf.decode(GAME_ENCODING), "Sword")

    def test_apply_gzip_compressed_release_json(self):
        """A gzip-compressed release JSON is auto-detected and applied."""
        import gzip as _gzip
        from src.import_data import apply_translations_from_release_json

        raw = self._build_game_binary(["Helmet", "Sword", "Shield"])
        game_dir = os.path.join(self.tmpdir, "game")
        dat_dir = os.path.join(game_dir, "dat")
        os.makedirs(dat_dir)
        bin_path = os.path.join(dat_dir, "mhfdat.bin")
        with open(bin_path, "wb") as f:
            f.write(raw)

        headers_path = os.path.join(self.tmpdir, "headers.json")
        with open(headers_path, "w", encoding="utf-8") as f:
            json.dump({"dat": {"armors": {"head": {
                "begin_pointer": "0x0",
                "next_field_pointer": "0x4",
            }}}}, f)

        payload = {"fr": {"dat/armors/head": [
            {"index": 0, "source": "Helmet", "target": "Casque"},
        ]}}
        gz_path = os.path.join(self.tmpdir, "translations.json.gz")
        with _gzip.open(gz_path, "wb") as f:
            f.write(json.dumps(payload, ensure_ascii=False).encode("utf-8"))

        results = apply_translations_from_release_json(
            gz_path, lang="fr", game_dir=game_dir,
            compress=False, encrypt=False,
            headers_path=headers_path,
        )
        self.assertEqual(results[os.path.join("dat", "mhfdat.bin")], 1)

    def test_apply_mixed_index_and_location(self):
        """A section may mix `index` entries with legacy `location` entries."""
        from src.import_data import apply_translations_from_release_json

        raw = self._build_game_binary(["Helmet", "Sword", "Shield"])
        game_dir = os.path.join(self.tmpdir, "game")
        dat_dir = os.path.join(game_dir, "dat")
        os.makedirs(dat_dir)
        bin_path = os.path.join(dat_dir, "mhfdat.bin")
        with open(bin_path, "wb") as f:
            f.write(raw)

        headers_path = os.path.join(self.tmpdir, "headers.json")
        with open(headers_path, "w", encoding="utf-8") as f:
            json.dump({
                "dat": {"armors": {"head": {
                    "begin_pointer": "0x0",
                    "next_field_pointer": "0x4",
                }}}
            }, f)

        # Mixed: slot 0 via index, slot 1 via legacy location (pointer @ 12)
        path = os.path.join(self.tmpdir, "mixed.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "fr": {
                    "dat/armors/head": [
                        {"index": 0, "source": "Helmet", "target": "Casque"},
                        {"location": "0xc@game.bin",
                         "source": "Sword", "target": "Epée"},
                    ]
                }
            }, f, ensure_ascii=False)

        results = apply_translations_from_release_json(
            path, lang="fr", game_dir=game_dir,
            compress=False, encrypt=False,
            headers_path=headers_path,
        )
        self.assertEqual(results[os.path.join("dat", "mhfdat.bin")], 2)

    def test_apply_indexed_unknown_xpath_skipped(self):
        """An indexed section whose xpath is missing from headers.json is
        skipped with a warning, not raised."""
        from src.import_data import apply_translations_from_release_json

        raw = self._build_game_binary(["A", "B"])
        game_dir = os.path.join(self.tmpdir, "game")
        dat_dir = os.path.join(game_dir, "dat")
        os.makedirs(dat_dir)
        with open(os.path.join(dat_dir, "mhfdat.bin"), "wb") as f:
            f.write(raw)

        headers_path = os.path.join(self.tmpdir, "headers.json")
        with open(headers_path, "w", encoding="utf-8") as f:
            json.dump({"dat": {}}, f)

        json_path = self._write_indexed_release_json("fr", {
            "dat/totally/unknown": [(0, "A", "Z")],
        })

        with self.assertLogs("src.import_data", level="WARNING") as cm:
            results = apply_translations_from_release_json(
                json_path, lang="fr", game_dir=game_dir,
                compress=False, encrypt=False,
                headers_path=headers_path,
            )
        self.assertEqual(results, {})
        self.assertTrue(
            any("xpath not found" in m for m in cm.output),
            f"expected unknown-xpath warning, got {cm.output}",
        )


if __name__ == "__main__":
    unittest.main()
