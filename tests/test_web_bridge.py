"""Tests for web/bridge.py, the glue the browser interface runs in Pyodide.

The bridge only orchestrates the tool, so extraction and import are
mocked; what is tested is the decode-once, apply-in-sequence and
re-encode logic around them. The page itself is exercised in a browser.
"""

import gzip
import io
import json
import logging
import os
import struct
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "web"))

import bridge  # noqa: E402
from src.common import GAME_ENCODING  # noqa: E402
from src.crypto import decrypt, encrypt, is_encrypted_file  # noqa: E402
from src.jkr_compress import compress_jkr_hfi  # noqa: E402
from src.jkr_decompress import decompress_jkr, is_jkr_file  # noqa: E402

PAYLOAD = b"decoded game data " * 64


def _pointer_table_binary(strings):
    """Header pointer, a pointer table at offset 8, then the strings."""
    table = 8
    offset = table + 4 * len(strings)
    pointers, blobs = [], []
    for text in strings:
        pointers.append(offset)
        blobs.append(text.encode(GAME_ENCODING) + b"\x00")
        offset += len(blobs[-1])
    return (struct.pack("<II", table, table + 4 * len(strings))
            + b"".join(struct.pack("<I", p) for p in pointers) + b"".join(blobs))


def _string_at_pointer(data, pointer):
    start = struct.unpack_from("<I", data, pointer)[0]
    return data[start:data.index(b"\x00", start)].decode(GAME_ENCODING)


class TestWebBridge(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        work = tmp.name
        for name, value in {
            "WORK": work,
            "INPUT_DIR": f"{work}/in",
            "DECODED_DIR": f"{work}/decoded",
            "TRANSLATION_DIR": f"{work}/translations",
        }.items():
            patcher = mock.patch.object(bridge, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        os.makedirs(bridge.INPUT_DIR)
        os.makedirs(bridge.TRANSLATION_DIR)
        root = logging.getLogger()
        self.addCleanup(setattr, root, "handlers", root.handlers[:])
        self.addCleanup(root.setLevel, root.level)
        self.addCleanup(setattr, bridge, "_reporter", bridge._reporter)
        self.messages = []
        bridge.set_reporter(self.messages.append)

    def _put_game_file(self, name, data):
        with open(f"{bridge.INPUT_DIR}/{name}", "wb") as f:
            f.write(data)

    def test_load_decodes_encrypted_compressed_file(self):
        self._put_game_file("mhfpac.bin", encrypt(compress_jkr_hfi(PAYLOAD)))
        info = bridge.load_game_file("mhfpac.bin")

        self.assertTrue(info["encrypted"])
        self.assertTrue(info["compressed"])
        self.assertEqual(info["decoded_size"], len(PAYLOAD))
        self.assertTrue(info["sections"])
        self.assertTrue(all(x.startswith("pac/") for x in info["sections"]))
        with open(f"{bridge.DECODED_DIR}/mhfpac.bin", "rb") as f:
            self.assertEqual(f.read(), PAYLOAD)

    def test_load_rejects_unknown_file_names(self):
        self._put_game_file("notes.bin", PAYLOAD)
        with self.assertRaisesRegex(ValueError, "does not look like a game data file"):
            bridge.load_game_file("notes.bin")

    def test_extract_zips_outputs_and_reports_failures(self):
        self._put_game_file("mhfdat.bin", PAYLOAD)
        bridge.load_game_file("mhfdat.bin")

        def fake_extract(source, xpath, _output_file, output_dir):
            if xpath == "dat/broken":
                raise ValueError("no readable data")
            stem = xpath.replace("/", "-")
            for ext in (".csv", ".json"):
                with open(f"{output_dir}/{stem}{ext}", "w") as f:
                    f.write(source)

        with mock.patch.object(bridge, "extract_from_file", side_effect=fake_extract):
            result = bridge.extract("mhfdat.bin", ["dat/armors/head", "dat/broken"])

        self.assertEqual(result["extracted"], ["dat/armors/head"])
        self.assertEqual(result["failed"], ["dat/broken"])
        names = zipfile.ZipFile(io.BytesIO(result["zip"])).namelist()
        self.assertEqual(names, ["dat-armors-head.csv", "dat-armors-head.json"])

    def test_build_applies_in_sequence_then_compresses_and_encrypts(self):
        self._put_game_file("mhfpac.bin", encrypt(compress_jkr_hfi(PAYLOAD)))
        bridge.load_game_file("mhfpac.bin")

        def fake_import(translation, source, output_path, fold_unsupported_chars):
            if translation.endswith("empty.csv"):
                return None
            with open(source, "rb") as f:
                data = f.read()
            with open(output_path, "wb") as f:
                f.write(data + os.path.basename(translation).encode())
            return output_path

        with mock.patch.object(bridge, "import_from_csv", side_effect=fake_import):
            result = bridge.build("mhfpac.bin", ["a.csv", "empty.csv", "b.json"])

        self.assertEqual(result["applied"], ["a.csv", "b.json"])
        self.assertEqual(result["unchanged"], ["empty.csv"])
        self.assertTrue(is_encrypted_file(result["data"]))
        decrypted, _ = decrypt(result["data"])
        self.assertTrue(is_jkr_file(decrypted))
        self.assertEqual(decompress_jkr(decrypted), PAYLOAD + b"a.csvb.json")

    def test_build_without_changes_skips_encoding(self):
        self._put_game_file("mhfpac.bin", PAYLOAD)
        bridge.load_game_file("mhfpac.bin")

        with mock.patch.object(bridge, "import_from_csv", return_value=None), \
                mock.patch.object(bridge, "compress_jkr_hfi") as compress:
            result = bridge.build("mhfpac.bin", ["empty.csv"])

        self.assertIsNone(result["data"])
        self.assertEqual(result["applied"], [])
        compress.assert_not_called()

    def _put_release(self, name, release):
        raw = json.dumps(release, ensure_ascii=False).encode("utf-8")
        with open(f"{bridge.TRANSLATION_DIR}/{name}", "wb") as f:
            f.write(gzip.compress(raw) if name.endswith(".gz") else raw)

    def test_stage_tells_releases_from_extracted_files(self):
        self._put_game_file("mhfdat.bin", PAYLOAD)
        bridge.load_game_file("mhfdat.bin")
        self._put_release("translations-fr.json.gz", {
            "fr": {"dat/armors/head": [], "dat/items/name": [], "pac/skills/name": []},
            "en": {"pac/skills/name": []},
        })
        with open(f"{bridge.TRANSLATION_DIR}/dat-armors-head.json", "w") as f:
            json.dump({"metadata": {"xpath": "dat/armors/head"}, "strings": []}, f)
        with open(f"{bridge.TRANSLATION_DIR}/dat-armors-head.csv", "w") as f:
            f.write("index,source,target\n")

        staged = bridge.stage_translations(
            "mhfdat.bin",
            ["translations-fr.json.gz", "dat-armors-head.json", "dat-armors-head.csv"],
        )

        self.assertEqual(staged, [
            {"name": "translations-fr.json.gz", "kind": "release",
             "languages": {"fr": 2, "en": 0}},
            {"name": "dat-armors-head.json", "kind": "section"},
            {"name": "dat-armors-head.csv", "kind": "section"},
        ])

    def test_build_applies_release_language_for_this_file_only(self):
        self._put_game_file("mhfdat.bin", _pointer_table_binary(["Helmet", "Sword"]))
        bridge.load_game_file("mhfdat.bin")
        self._put_release("translations-fr.json.gz", {"fr": {
            "dat/armors/head": [{"location": "0x8@mhfdat.bin", "target": "Casque élite"}],
            # Belongs to mhfpac.bin: must not be reported as a missing file.
            "pac/skills/name": [{"location": "0x8@mhfpac.bin", "target": "Garde"}],
        }})
        bridge.stage_translations("mhfdat.bin", ["translations-fr.json.gz"])

        result = bridge.build(
            "mhfdat.bin", ["translations-fr.json.gz"],
            release_languages={"translations-fr.json.gz": "fr"},
            compress=False, encrypt_output=False,
        )

        self.assertEqual(result["applied"], ["translations-fr.json.gz"])
        self.assertEqual(_string_at_pointer(result["data"], 8), "Casque elite")
        self.assertEqual(_string_at_pointer(result["data"], 12), "Sword")
        self.assertFalse(any("not found" in m for m in self.messages))

    def test_build_reports_release_without_sections_for_this_file(self):
        self._put_game_file("mhfdat.bin", _pointer_table_binary(["Helmet"]))
        bridge.load_game_file("mhfdat.bin")
        self._put_release("translations-en.json", {"en": {
            "pac/skills/name": [{"location": "0x8@mhfpac.bin", "target": "Guard"}],
        }})
        bridge.stage_translations("mhfdat.bin", ["translations-en.json"])

        result = bridge.build(
            "mhfdat.bin", ["translations-en.json"],
            release_languages={"translations-en.json": "en"},
        )

        self.assertIsNone(result["data"])
        self.assertEqual(result["unchanged"], ["translations-en.json"])



# A flat pointer table at 8 (see _pointer_table_binary), with limits.
SECTION = {"begin_pointer": "0x0", "next_field_pointer": "0x4",
           "max_display_width": 12, "max_sub_count": 1}


class TestWebEditor(unittest.TestCase):
    """The in-page editor's bridge functions."""

    setUp = TestWebBridge.setUp
    _put_game_file = TestWebBridge._put_game_file
    _put_release = TestWebBridge._put_release

    def _load(self, strings):
        self._put_game_file("mhfdat.bin", _pointer_table_binary(strings))
        bridge.load_game_file("mhfdat.bin")
        patcher = mock.patch.object(bridge.common, "read_extraction_config", return_value=SECTION)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_section_rows(self):
        self._load(["Helmet", "Sword"])
        self.assertEqual(
            bridge.section_rows("mhfdat.bin", "dat/armors/head"),
            {"sources": ["Helmet", "Sword"], "max_width": 12, "max_subs": 1},
        )

    def test_search_sections(self):
        self._load(["Helmet", "Iron Sword", "sword of fire"])
        found = bridge.search_sections("mhfdat.bin", "SWORD")
        dat_sections = [x for x in bridge.common.get_all_xpaths() if x.startswith("dat/")]
        # read_extraction_config is mocked: every dat section reads the same table.
        self.assertEqual(found, [[x, 2] for x in dat_sections])
        self.assertEqual(bridge.search_sections("mhfdat.bin", "shield"), [])

    def test_search_sections_forgets_a_replaced_file(self):
        self._load(["Helmet"])
        self.assertEqual(bridge.search_sections("mhfdat.bin", "sword"), [])
        self._put_game_file("mhfdat.bin", _pointer_table_binary(["Sword"]))
        bridge.load_game_file("mhfdat.bin")
        self.assertTrue(bridge.search_sections("mhfdat.bin", "sword"))

    def test_check_rows(self):
        self._load(["Helmet"])
        results = bridge.check_rows("dat/armors/head", [
            ["Helmet", "Casque"],
            ["{c05}Fire{/c}", "Feu{/c}"],
            ["Helmet", "Casque d'élite"],
            ["Helmet", "Casque 🙂"],
            ["Helmet", "A{j}B"],
        ])
        self.assertEqual(results[0], [])
        self.assertEqual(results[1], [
            {"kind": "placeholder", "marker": "{c05}", "source": 1, "target": 0}])
        self.assertEqual(results[2], [
            {"kind": "folded", "text": "Casque d'elite"},
            {"kind": "width", "sub": 0, "width": 14, "max": 12}])
        self.assertEqual([i["kind"] for i in results[3]], ["unencodable"])
        self.assertEqual(results[3][0]["chars"], "🙂")
        self.assertIn({"kind": "subs", "count": 2, "max": 1}, results[4])

    def test_export_edits_writes_standard_json(self):
        self._load(["Helmet", "Sword"])
        archive = zipfile.ZipFile(io.BytesIO(
            bridge.export_edits("mhfdat.bin", {"dat/armors/head": {"1": "Epee", "0": ""}})
        ))
        self.assertEqual(archive.namelist(), ["dat-armors-head.json"])
        document = json.loads(archive.read("dat-armors-head.json"))
        self.assertEqual(document["metadata"]["xpath"], "dat/armors/head")
        self.assertEqual(document["metadata"]["source_file"], "mhfdat.bin")
        self.assertEqual([row["target"] for row in document["strings"]], ["", "Epee"])

    def test_build_applies_editor_edits_after_files(self):
        self._load(["Helmet", "Sword"])
        with open(f"{bridge.TRANSLATION_DIR}/dat-armors-head.csv", "w") as f:
            f.write("index,source,target\n0,Helmet,Heaume\n1,Sword,Lame\n")
        bridge.stage_translations("mhfdat.bin", ["dat-armors-head.csv"])

        result = bridge.build(
            "mhfdat.bin", ["dat-armors-head.csv"],
            edits={"dat/armors/head": {"0": "Casque élite"}},
            compress=False, encrypt_output=False,
        )

        self.assertEqual(result["applied"], ["dat-armors-head.csv", "editor-dat-armors-head.json"])
        self.assertEqual(_string_at_pointer(result["data"], 8), "Casque elite")
        self.assertEqual(_string_at_pointer(result["data"], 12), "Lame")

    def test_read_edits(self):
        self._load(["Helmet", "Sword"])
        with open(f"{bridge.TRANSLATION_DIR}/dat-armors-head.csv", "w") as f:
            f.write("index,source,target\n0,Helmet,Casque\n1,Sword,\n")
        with open(f"{bridge.TRANSLATION_DIR}/pac-skills-name.csv", "w") as f:
            f.write("index,source,target\n0,Guard,Garde\n")
        with open(f"{bridge.TRANSLATION_DIR}/old.csv", "w") as f:
            f.write("location,source,target\n0x8@mhfdat.bin,Helmet,Casque\n")
        self._put_release("translations-fr.json.gz", {"fr": {
            "dat/items/name": [{"index": "3", "target": "Potion"}, {"index": 4, "target": ""}],
            "pac/skills/name": [{"index": 0, "target": "Garde"}],
        }})
        names = ["dat-armors-head.csv", "pac-skills-name.csv", "old.csv", "translations-fr.json.gz"]
        bridge.stage_translations("mhfdat.bin", names)

        result = bridge.read_edits("mhfdat.bin", names, {"translations-fr.json.gz": "fr"})

        self.assertEqual(result["edits"], {
            "dat/armors/head": {0: "Casque"},
            "dat/items/name": {3: "Potion"},
        })
        self.assertEqual(result["skipped"], [
            {"name": "pac-skills-name.csv", "reason": "other_file"},
            {"name": "old.csv", "reason": "legacy"},
        ])


if __name__ == "__main__":
    unittest.main()
