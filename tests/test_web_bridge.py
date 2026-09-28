"""Tests for web/bridge.py, the glue the browser interface runs in Pyodide.

The bridge only orchestrates the tool, so extraction and import are
mocked; what is tested is the decode-once, apply-in-sequence and
re-encode logic around them. The page itself is exercised in a browser.
"""

import io
import logging
import os
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "web"))

import bridge  # noqa: E402
from src.crypto import decrypt, encrypt, is_encrypted_file  # noqa: E402
from src.jkr_compress import compress_jkr_hfi  # noqa: E402
from src.jkr_decompress import decompress_jkr, is_jkr_file  # noqa: E402

PAYLOAD = b"decoded game data " * 64


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


if __name__ == "__main__":
    unittest.main()
