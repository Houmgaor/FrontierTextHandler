"""
``--fold-unsupported-chars`` on the standalone importers.

The flag used to be wired only into ``--csv-to-bin``. Under CP932 an
accented target either folds or fails to encode, so the FTXT, scenario
and NPC-dialogue importers must honour it too: off -> ``EncodingError``,
on -> ASCII-folded text in the rebuilt file.
"""

import csv
import os
import tempfile
import unittest

from src.common import EncodingError, extract_ftxt_data, extract_npc_dialogue
from src.export import (
    extract_ftxt_file,
    extract_npc_dialogue_file,
    extract_scenario_file as extract_scenario_file_export,
)
from src.import_data import (
    import_ftxt_from_csv,
    import_npc_dialogue_from_csv,
    import_scenario_from_csv,
)
from src.scenario import extract_scenario_file

from tests.test_ftxt_quest import build_ftxt
from tests.test_npc_dialogue import build_npc_dialogue
from tests.test_scenario import build_scenario_file

ACCENTED = "Épée"  # short: scenario chunk0 slots are fixed-width
FOLDED = "Epee"


def _translate_first_row(csv_path: str, target: str) -> str:
    """Copy ``csv_path`` next to itself with the first data row's target set."""
    with open(csv_path, "r", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    rows[1][2] = target
    edited = os.path.join(os.path.dirname(csv_path), "edited.csv")
    with open(edited, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(rows)
    return edited


class TestFoldOnStandaloneImporters(unittest.TestCase):

    def _check(self, data, extract_csv, importer, read_first):
        with tempfile.TemporaryDirectory() as tmpdir:
            source = os.path.join(tmpdir, "source.bin")
            with open(source, "wb") as f:
                f.write(data)
            csv_path, _, _ = extract_csv(source, output_dir=tmpdir)
            edited = _translate_first_row(csv_path, ACCENTED)
            out = os.path.join(tmpdir, "modified.bin")

            with self.assertRaises(EncodingError):
                importer(edited, source, output_path=out)

            result = importer(
                edited, source, output_path=out, fold_unsupported_chars=True
            )
            self.assertIsNotNone(result)
            self.assertEqual(read_first(out), FOLDED)

    def test_ftxt(self):
        def read_first(path):
            with open(path, "rb") as f:
                return extract_ftxt_data(f.read())[0]["text"]

        self._check(
            build_ftxt(["Alpha", "Beta"]),
            extract_ftxt_file, import_ftxt_from_csv, read_first,
        )

    def test_scenario(self):
        self._check(
            build_scenario_file(
                chunk0_strings=["Original1", "Original2"],
                chunk1_strings=["Dialog1"],
            ),
            extract_scenario_file_export, import_scenario_from_csv,
            lambda path: extract_scenario_file(path)[0]["text"],
        )

    def test_npc_dialogue(self):
        self._check(
            build_npc_dialogue([(1, ["Hello"]), (2, ["World"])]),
            extract_npc_dialogue_file, import_npc_dialogue_from_csv,
            lambda path: extract_npc_dialogue(path)[0]["text"],
        )


if __name__ == "__main__":
    unittest.main()
