"""End-to-end round-trip tests for the full extraction/import pipeline."""

import csv
import os
import struct
import tempfile
import unittest

from src.common import (
    FTXT_HEADER_SIZE,
    FTXT_MAGIC,
    GAME_ENCODING,
    extract_ftxt_data,
    extract_npc_dialogue_data,
    extract_text_data_from_bytes,
    split_join_text,
)
from src.binary_file import BinaryFile
from src.export import export_as_csv, export_as_json
from src.import_data import (
    get_new_strings,
    get_new_strings_from_json,
    rebuild_ftxt,
    rebuild_section,
    rebuild_npc_dialogue,
    parse_joined_text,
)


class TestStandardPointerRoundTrip(unittest.TestCase):
    """Test extract → CSV → import → re-extract for standard pointer-pair mode."""

    def _build_binary(self, strings: list[str]) -> tuple[bytes, dict]:
        """Build a minimal binary with standard pointer-pair layout."""
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

        config = {
            "begin_pointer": "0x0",
            "next_field_pointer": "0x4",
        }
        return bytes(data), config

    def test_roundtrip_no_translation(self):
        """Extract → CSV → import (no changes) → re-extract produces same strings."""
        original_strings = ["Sword of Light", "Shield of Darkness", "Helm of Wisdom"]
        data, config = self._build_binary(original_strings)

        # Extract
        results = extract_text_data_from_bytes(data, config)
        self.assertEqual(len(results), 3)

        # Export to CSV
        fd, csv_path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.unlink, csv_path)
        export_as_csv(results, csv_path, "test.bin")

        # Import (source == target, so no changes)
        new_strings = get_new_strings(csv_path)
        self.assertEqual(new_strings, [])  # No changes

    def test_roundtrip_with_translation(self):
        """Extract → edit CSV → import → re-extract shows translated strings."""
        original_strings = ["Original A", "Original B"]
        data, config = self._build_binary(original_strings)

        # Extract
        results = extract_text_data_from_bytes(data, config)

        # Write CSV with translation in target column
        fd, csv_path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.unlink, csv_path)

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            for r in results:
                location = f"0x{r['offset']:x}@test.bin"
                writer.writerow([location, r["text"], f"Translated {r['text']}"])

        # Import via rebuild_section
        fd, output_path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        self.addCleanup(os.unlink, output_path)

        new_strings = get_new_strings(csv_path)
        self.assertEqual(len(new_strings), 2)

        rebuild_section(data, config, new_strings, output_path)

        # Re-extract from rebuilt binary
        with open(output_path, "rb") as f:
            rebuilt_data = f.read()
        re_results = extract_text_data_from_bytes(rebuilt_data, config)

        self.assertEqual(len(re_results), 2)
        self.assertEqual(re_results[0]["text"], "Translated Original A")
        self.assertEqual(re_results[1]["text"], "Translated Original B")

    def test_roundtrip_partial_translation(self):
        """Only some strings are translated; others remain unchanged."""
        original_strings = ["Keep", "Translate Me", "Keep Too"]
        data, config = self._build_binary(original_strings)

        results = extract_text_data_from_bytes(data, config)

        fd, csv_path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.unlink, csv_path)

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            for r in results:
                location = f"0x{r['offset']:x}@test.bin"
                if r["text"] == "Translate Me":
                    writer.writerow([location, r["text"], "Translated"])
                else:
                    writer.writerow([location, r["text"], r["text"]])

        new_strings = get_new_strings(csv_path)
        self.assertEqual(len(new_strings), 1)

        fd, output_path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        self.addCleanup(os.unlink, output_path)

        rebuild_section(data, config, new_strings, output_path)

        with open(output_path, "rb") as f:
            rebuilt_data = f.read()
        re_results = extract_text_data_from_bytes(rebuilt_data, config)

        self.assertEqual(re_results[0]["text"], "Keep")
        self.assertEqual(re_results[1]["text"], "Translated")
        self.assertEqual(re_results[2]["text"], "Keep Too")


class TestIndexedRoundTrip(unittest.TestCase):
    """Index-keyed CSV/JSON survives offset shifts caused by length changes."""

    def _build_binary(self, strings):
        return TestStandardPointerRoundTrip._build_binary(self, strings)

    def test_indexed_csv_roundtrip(self):
        from src.import_data import (
            detect_translation_format,
            get_new_strings_indexed,
            resolve_indexes_to_offsets,
        )

        original = ["A", "B", "C"]
        data, config = self._build_binary(original)
        results = extract_text_data_from_bytes(data, config)

        fd, csv_path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.unlink, csv_path)
        export_as_csv(results, csv_path, "test.bin", with_index=True)

        # New format: three columns, no offset/filename
        with open(csv_path, encoding="utf-8") as f:
            header = next(csv.reader(f))
        self.assertEqual(header, ["index", "source", "target"])

        self.assertEqual(detect_translation_format(csv_path), "index")

        # Edit: translate slot 1 to a much longer string
        with open(csv_path, encoding="utf-8") as f:
            rows = list(csv.reader(f))
        rows[2][2] = "Bee" * 50  # target column
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(rows)

        # Now mutate the underlying binary so all offsets shift:
        # rebuild it with longer original strings — slot 1 keeps its
        # *index* but lives at a different *offset*.
        shifted_originals = ["A" * 30, "B", "C" * 40]
        shifted_data, _ = self._build_binary(shifted_originals)

        indexed = get_new_strings_indexed(csv_path)
        self.assertEqual(len(indexed), 1)
        self.assertEqual(indexed[0][0], 1)

        resolved = resolve_indexes_to_offsets(indexed, shifted_data, config)
        # Resolved offset must point at slot 1 in the shifted file
        shifted_entries = extract_text_data_from_bytes(shifted_data, config)
        self.assertEqual(resolved[0][0], shifted_entries[1]["offset"])
        self.assertEqual(resolved[0][1], "Bee" * 50)


    def test_indexed_full_roundtrip_with_translation(self):
        """End-to-end: extract → edit index CSV → import → re-extract.

        This is the canonical proof that the new index-keyed format
        actually works for its primary use case. Mirrors
        ``test_roundtrip_with_translation`` from the legacy format.
        """
        import json as _json
        from src.import_data import import_from_csv

        original = ["First", "Second", "Third"]
        data, config = self._build_binary(original)

        with tempfile.TemporaryDirectory() as tmp:
            # 1. Write source binary + a tiny headers.json
            bin_path = os.path.join(tmp, "src.bin")
            with open(bin_path, "wb") as f:
                f.write(data)
            headers_path = os.path.join(tmp, "headers.json")
            with open(headers_path, "w", encoding="utf-8") as f:
                _json.dump({"test": {"section": config}}, f)

            # 2. Extract to index-keyed CSV
            csv_path = os.path.join(tmp, "test-section.csv")
            export_as_csv(
                extract_text_data_from_bytes(data, config),
                csv_path, "src.bin", with_index=True,
            )

            # 3. Edit two of the three slots
            with open(csv_path, encoding="utf-8") as f:
                rows = list(csv.reader(f))
            self.assertEqual(rows[0], ["index", "source", "target"])
            rows[1][2] = "Premier"   # slot 0
            rows[3][2] = "Troisieme" # slot 2
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows(rows)

            # 4. Import (no --xpath; should infer from filename)
            out_path = os.path.join(tmp, "out.bin")
            result = import_from_csv(
                csv_path, bin_path, output_path=out_path,
                headers_path=headers_path,
            )
            self.assertEqual(result, out_path)

            # 5. Re-extract and verify the translations landed at the
            #    right slots and the untranslated middle entry is intact
            with open(out_path, "rb") as f:
                rebuilt = f.read()
            re_results = extract_text_data_from_bytes(rebuilt, config)
            self.assertEqual(len(re_results), 3)
            self.assertEqual(re_results[0]["text"], "Premier")
            self.assertEqual(re_results[1]["text"], "Second")
            self.assertEqual(re_results[2]["text"], "Troisieme")

    def test_indexed_extract_is_deterministic_no_op(self):
        """Extract → import (no edits) → re-extract is a true no-op.

        Locks in:
          * extracting the same binary twice yields byte-identical CSV
          * importing an unedited index-keyed CSV does not modify the binary
        """
        from src.import_data import import_from_csv

        original = ["alpha", "bravo", "charlie"]
        data, config = self._build_binary(original)

        with tempfile.TemporaryDirectory() as tmp:
            bin_path = os.path.join(tmp, "test.bin")
            with open(bin_path, "wb") as f:
                f.write(data)

            csv1 = os.path.join(tmp, "first.csv")
            csv2 = os.path.join(tmp, "second.csv")
            export_as_csv(
                extract_text_data_from_bytes(data, config),
                csv1, "test.bin", with_index=True,
            )
            export_as_csv(
                extract_text_data_from_bytes(data, config),
                csv2, "test.bin", with_index=True,
            )
            with open(csv1, "rb") as f:
                bytes1 = f.read()
            with open(csv2, "rb") as f:
                bytes2 = f.read()
            self.assertEqual(bytes1, bytes2, "extraction must be deterministic")

            # Import unedited CSV: should be a no-op (returns None, no output).
            # We pass the live config via a temporary headers.json so xpath
            # validation succeeds without touching the real file.
            import json as _json
            headers_path = os.path.join(tmp, "headers.json")
            with open(headers_path, "w", encoding="utf-8") as f:
                _json.dump({"test": {"section": config}}, f)

            result = import_from_csv(
                csv1, bin_path, output_path=os.path.join(tmp, "out.bin"),
                xpath="test/section", headers_path=headers_path,
            )
            self.assertIsNone(result, "no-op import should not write a file")

    def test_xpath_inferred_from_json_metadata(self):
        """Index-keyed JSON with metadata.xpath needs no --xpath at import."""
        from src.import_data import infer_xpath
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "anything.json")
            import json as _json
            with open(json_path, "w", encoding="utf-8") as f:
                _json.dump({
                    "metadata": {"source_file": "x.bin", "xpath": "dat/armors/head"},
                    "strings": [{"index": 0, "source": "a", "target": "a"}],
                }, f)
            self.assertEqual(infer_xpath(json_path), "dat/armors/head")

    def test_xpath_inferred_from_csv_filename(self):
        """`dat-armors-head.csv` resolves to xpath `dat/armors/head`."""
        from src.import_data import infer_xpath
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "dat-armors-head.csv")
            with open(csv_path, "w", encoding="utf-8") as f:
                f.write("index,source,target\n0,a,a\n")
            # Real headers.json contains dat/armors/head
            self.assertEqual(infer_xpath(csv_path), "dat/armors/head")

    def test_fingerprint_in_json_metadata_and_mismatch_warning(self):
        """JSON export records a fingerprint; importer warns on mismatch."""
        import json as _json
        import logging as _logging
        from src.common import compute_binary_fingerprint
        from src.export import export_as_json
        from src.import_data import import_from_csv

        original = ["alpha", "bravo", "charlie"]
        data, config = self._build_binary(original)

        with tempfile.TemporaryDirectory() as tmp:
            # Build a tiny headers.json so we can pass an xpath
            headers_path = os.path.join(tmp, "headers.json")
            with open(headers_path, "w", encoding="utf-8") as f:
                _json.dump({"test": {"section": config}}, f)

            entries = extract_text_data_from_bytes(data, config)
            json_path = os.path.join(tmp, "test-section.json")
            export_as_json(
                entries, json_path, "test.bin",
                with_index=True, xpath="test/section",
                fingerprint=compute_binary_fingerprint(data),
            )

            # Metadata block records the fingerprint and xpath
            with open(json_path, encoding="utf-8") as f:
                meta = _json.load(f)["metadata"]
            self.assertEqual(meta["fingerprint"], compute_binary_fingerprint(data))
            self.assertEqual(meta["xpath"], "test/section")

            # Edit one target so import has work to do
            with open(json_path, "r", encoding="utf-8") as f:
                payload = _json.load(f)
            payload["strings"][1]["target"] = "BRAVO!"
            with open(json_path, "w", encoding="utf-8") as f:
                _json.dump(payload, f)

            # Match: no warning
            bin_path = os.path.join(tmp, "test.bin")
            with open(bin_path, "wb") as f:
                f.write(data)
            with self.assertLogs("src.import_data", level="INFO") as cm:
                import_from_csv(
                    json_path, bin_path,
                    output_path=os.path.join(tmp, "out_match.bin"),
                    xpath="test/section", headers_path=headers_path,
                )
            self.assertTrue(
                any("fingerprint" in m and "matches" in m for m in cm.output),
                f"expected match log, got {cm.output}",
            )
            self.assertFalse(
                any("mismatch" in m.lower() for m in cm.output),
            )

            # Mismatch: import a different binary, expect a WARNING
            other_data, _ = self._build_binary(["x", "y", "z"])
            other_path = os.path.join(tmp, "other.bin")
            with open(other_path, "wb") as f:
                f.write(other_data)
            with self.assertLogs("src.import_data", level="WARNING") as cm:
                import_from_csv(
                    json_path, other_path,
                    output_path=os.path.join(tmp, "out_mismatch.bin"),
                    xpath="test/section", headers_path=headers_path,
                )
            self.assertTrue(
                any("fingerprint mismatch" in m.lower() for m in cm.output),
                f"expected mismatch warning, got {cm.output}",
            )

    def test_xpath_inference_returns_none_when_unknown(self):
        from src.import_data import infer_xpath
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "totally-bogus-name.csv")
            with open(csv_path, "w", encoding="utf-8") as f:
                f.write("index,source,target\n")
            self.assertIsNone(infer_xpath(csv_path))


class TestFtxtRoundTrip(unittest.TestCase):
    """Test extract → CSV → import → re-extract for FTXT files."""

    def _build_ftxt(self, strings: list[str]) -> bytes:
        text_parts = []
        for s in strings:
            text_parts.append(s.encode(GAME_ENCODING) + b"\x00")
        text_block = b"".join(text_parts)
        header = struct.pack("<I6xHI", FTXT_MAGIC, len(strings), len(text_block))
        return header + text_block

    def _write_temp(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.write(fd, data)
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_ftxt_roundtrip(self):
        """Extract FTXT → CSV → import → re-extract."""
        original = self._build_ftxt(["Hello FTXT", "World FTXT"])
        source_path = self._write_temp(original)

        # Extract
        results = extract_ftxt_data(original)
        self.assertEqual(len(results), 2)

        # Write CSV with translations
        fd, csv_path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.unlink, csv_path)

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["location", "source", "target"])
            for r in results:
                location = f"0x{r['offset']:x}@test.bin"
                writer.writerow([location, r["text"], f"TR:{r['text']}"])

        # Import
        from src.import_data import get_new_strings
        new_strings = get_new_strings(csv_path)

        fd, output_path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        self.addCleanup(os.unlink, output_path)

        rebuild_ftxt(source_path, new_strings, output_path)

        # Re-extract
        with open(output_path, "rb") as f:
            rebuilt = f.read()
        re_results = extract_ftxt_data(rebuilt)

        self.assertEqual(len(re_results), 2)
        self.assertEqual(re_results[0]["text"], "TR:Hello FTXT")
        self.assertEqual(re_results[1]["text"], "TR:World FTXT")


class TestNpcDialogueRoundTrip(unittest.TestCase):
    """Test extract → import → re-extract for NPC dialogue."""

    def _build_npc_dialogue(
        self, npcs: list[tuple[int, list[str]]]
    ) -> bytes:
        """Build a minimal NPC dialogue binary.

        npcs: list of (npc_id, [dialogue_strings])
        """
        num_npcs = len(npcs)
        npc_table_size = (num_npcs + 1) * 8  # +1 for terminator

        blocks: list[bytes] = []
        block_offsets: list[int] = []
        current_offset = npc_table_size

        for npc_id, dialogues in npcs:
            block_offsets.append(current_offset)
            if not dialogues:
                block = struct.pack("<I", 0)
            else:
                num_dlg = len(dialogues)
                header_size = num_dlg * 4
                encoded = [d.encode(GAME_ENCODING) + b"\x00" for d in dialogues]
                pointers_section = 4 + num_dlg * 4
                string_off = pointers_section
                rel_ptrs = []
                for enc in encoded:
                    rel_ptrs.append(string_off)
                    string_off += len(enc)

                block = bytearray()
                block.extend(struct.pack("<I", header_size))
                for rp in rel_ptrs:
                    block.extend(struct.pack("<I", rp))
                for enc in encoded:
                    block.extend(enc)
                block = bytes(block)

            blocks.append(block)
            current_offset += len(block)

        # Build output
        output = bytearray()
        for i, (npc_id, _) in enumerate(npcs):
            output.extend(struct.pack("<I", npc_id))
            output.extend(struct.pack("<I", block_offsets[i]))
        # Terminator
        output.extend(struct.pack("<I", 0xFFFFFFFF))
        output.extend(struct.pack("<I", 0xFFFFFFFF))
        for block in blocks:
            output.extend(block)

        return bytes(output)

    def _write_temp(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.write(fd, data)
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_npc_roundtrip(self):
        """Build → extract → import with translations → re-extract."""
        original = self._build_npc_dialogue([
            (1, ["Hello traveler", "Safe hunting"]),
            (2, ["Welcome to the shop"]),
        ])
        source_path = self._write_temp(original)

        # Extract
        results = extract_npc_dialogue_data(original)
        self.assertEqual(len(results), 2)

        # Build translations (translate NPC 1's dialogue)
        table_offset = results[0]["offset"]
        original_text = results[0]["text"]
        parts = split_join_text(original_text)
        self.assertEqual(len(parts), 2)

        # Rebuild join text with translations
        pairs = parse_joined_text(table_offset, original_text)
        translated_text = 'Bonjour voyageur<join at="' + str(pairs[1][0]) + '">Bonne chasse'
        new_strings = [(table_offset, translated_text)]

        fd, output_path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        self.addCleanup(os.unlink, output_path)

        rebuild_npc_dialogue(source_path, new_strings, output_path)

        # Re-extract
        with open(output_path, "rb") as f:
            rebuilt = f.read()
        re_results = extract_npc_dialogue_data(rebuilt)

        self.assertEqual(len(re_results), 2)
        npc1_parts = split_join_text(re_results[0]["text"])
        self.assertEqual(npc1_parts[0], "Bonjour voyageur")
        self.assertEqual(npc1_parts[1], "Bonne chasse")
        # NPC 2 unchanged
        npc2_parts = split_join_text(re_results[1]["text"])
        self.assertEqual(npc2_parts[0], "Welcome to the shop")


class TestJsonRoundTrip(unittest.TestCase):
    """Test extract → JSON → import round-trip."""

    def _build_binary(self, strings: list[str]) -> tuple[bytes, dict]:
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

        config = {
            "begin_pointer": "0x0",
            "next_field_pointer": "0x4",
        }
        return bytes(data), config

    def test_json_roundtrip(self):
        """Legacy-form JSON round-trip via the ``with_index=False``
        opt-out. Kept for backward compatibility of the offset-keyed
        JSON parser ``get_new_strings_from_json``."""
        original_strings = ["Item A", "Item B"]
        data, config = self._build_binary(original_strings)

        results = extract_text_data_from_bytes(data, config)

        # Export as legacy offset-keyed JSON so the legacy parser
        # finds ``location`` keys below.
        fd, json_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.addCleanup(os.unlink, json_path)
        export_as_json(results, json_path, "test.bin", with_index=False)

        # Modify JSON to add translations
        import json
        with open(json_path, "r") as f:
            json_data = json.load(f)
        for entry in json_data["strings"]:
            entry["target"] = f"TR:{entry['source']}"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        # Import via the legacy ``location``-keyed parser.
        new_strings = get_new_strings_from_json(json_path)
        self.assertEqual(len(new_strings), 2)

        fd, output_path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        self.addCleanup(os.unlink, output_path)

        rebuild_section(data, config, new_strings, output_path)

        with open(output_path, "rb") as f:
            rebuilt = f.read()
        re_results = extract_text_data_from_bytes(rebuilt, config)

        self.assertEqual(re_results[0]["text"], "TR:Item A")
        self.assertEqual(re_results[1]["text"], "TR:Item B")


class TestJapaneseRoundTrip(unittest.TestCase):
    """Test round-trip with Japanese text (Shift-JIS encoding)."""

    def _build_binary(self, strings: list[str]) -> tuple[bytes, dict]:
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

        config = {"begin_pointer": "0x0", "next_field_pointer": "0x4"}
        return bytes(data), config

    def test_japanese_roundtrip(self):
        """Japanese text survives extract → import round-trip."""
        strings = ["大剣", "太刀", "片手剣"]
        data, config = self._build_binary(strings)

        results = extract_text_data_from_bytes(data, config)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["text"], "大剣")

        # Translate one string
        new_strings = [(results[1]["offset"], "Katana")]

        fd, output_path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        self.addCleanup(os.unlink, output_path)

        rebuild_section(data, config, new_strings, output_path)

        with open(output_path, "rb") as f:
            rebuilt = f.read()
        re_results = extract_text_data_from_bytes(rebuilt, config)

        self.assertEqual(re_results[0]["text"], "大剣")
        self.assertEqual(re_results[1]["text"], "Katana")
        self.assertEqual(re_results[2]["text"], "片手剣")


if __name__ == "__main__":
    unittest.main()
