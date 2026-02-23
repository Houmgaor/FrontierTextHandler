"""
Tests for the merge module.

Tests translation carryover between old translated and freshly extracted CSV/JSON files.
"""
import csv
import json
import os
import tempfile
import unittest

from src import (
    MergeResult,
    merge_translations,
    write_merged_csv,
    write_merged,
    format_merge_report,
)
from src.merge import (
    load_translations_from_csv,
    load_translations_from_json,
    load_translations,
    write_merged_json,
)


def _write_csv(path: str, rows: list[list[str]]) -> None:
    """Write a CSV file with header + rows."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["location", "source", "target"])
        for row in rows:
            writer.writerow(row)


def _write_json(path: str, rows: list[list[str]], source_file: str = "test.bin") -> None:
    """Write a JSON file with metadata + string entries."""
    strings = []
    for row in rows:
        strings.append({
            "location": row[0],
            "source": row[1],
            "target": row[2],
        })
    data = {
        "metadata": {"source_file": source_file, "version": "1.2.0"},
        "strings": strings,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _read_csv_rows(path: str) -> list[list[str]]:
    """Read CSV rows (skipping header)."""
    with open(path, "r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)  # skip header
        return [row for row in reader if row]


def _read_json_strings(path: str) -> list[dict]:
    """Read JSON string entries."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["strings"]


class TestLoadTranslationsCSV(unittest.TestCase):
    """Tests for load_translations_from_csv."""

    def test_load_basic(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            path = f.name
        try:
            _write_csv(path, [
                ["0x10@mhfdat.bin", "Hello", "Bonjour"],
                ["0x20@mhfdat.bin", "World", "Monde"],
            ])
            result = load_translations_from_csv(path)
            self.assertEqual(result["0x10"], ("Hello", "Bonjour"))
            self.assertEqual(result["0x20"], ("World", "Monde"))
        finally:
            os.unlink(path)

    def test_strips_filename(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            path = f.name
        try:
            _write_csv(path, [["0xabc@file.bin", "Test", "Translated"]])
            result = load_translations_from_csv(path)
            self.assertIn("0xabc", result)
        finally:
            os.unlink(path)

    def test_empty_csv(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            path = f.name
        try:
            _write_csv(path, [])
            result = load_translations_from_csv(path)
            self.assertEqual(result, {})
        finally:
            os.unlink(path)


class TestLoadTranslationsJSON(unittest.TestCase):
    """Tests for load_translations_from_json."""

    def test_load_basic(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            _write_json(path, [
                ["0x10@mhfdat.bin", "Hello", "Bonjour"],
                ["0x20@mhfdat.bin", "World", "Monde"],
            ])
            result = load_translations_from_json(path)
            self.assertEqual(result["0x10"], ("Hello", "Bonjour"))
            self.assertEqual(result["0x20"], ("World", "Monde"))
        finally:
            os.unlink(path)

    def test_empty_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            _write_json(path, [])
            result = load_translations_from_json(path)
            self.assertEqual(result, {})
        finally:
            os.unlink(path)


class TestLoadTranslationsAutoDetect(unittest.TestCase):
    """Tests for load_translations auto-detection."""

    def test_detects_csv(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            path = f.name
        try:
            _write_csv(path, [["0x10@f.bin", "A", "B"]])
            result = load_translations(path)
            self.assertEqual(result["0x10"], ("A", "B"))
        finally:
            os.unlink(path)

    def test_detects_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            _write_json(path, [["0x10@f.bin", "A", "B"]])
            result = load_translations(path)
            self.assertEqual(result["0x10"], ("A", "B"))
        finally:
            os.unlink(path)


class TestMergeTranslations(unittest.TestCase):
    """Tests for merge_translations core logic."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def _old_path(self, ext=".csv"):
        return os.path.join(self.tmpdir, f"old{ext}")

    def _new_path(self, ext=".csv"):
        return os.path.join(self.tmpdir, f"new{ext}")

    def test_carry_translation(self):
        """Same offset + same source + translation exists -> carry over."""
        _write_csv(self._old_path(), [
            ["0x10@f.bin", "Hello", "Bonjour"],
        ])
        _write_csv(self._new_path(), [
            ["0x10@f.bin", "Hello", "Hello"],
        ])
        result, rows = merge_translations(self._old_path(), self._new_path())
        self.assertEqual(result.carried, 1)
        self.assertEqual(rows[0]["target"], "Bonjour")

    def test_unchanged_no_translation(self):
        """Same offset + same source + no translation -> unchanged."""
        _write_csv(self._old_path(), [
            ["0x10@f.bin", "Hello", "Hello"],
        ])
        _write_csv(self._new_path(), [
            ["0x10@f.bin", "Hello", "Hello"],
        ])
        result, rows = merge_translations(self._old_path(), self._new_path())
        self.assertEqual(result.unchanged, 1)
        self.assertEqual(result.carried, 0)
        self.assertEqual(rows[0]["target"], "Hello")

    def test_modified_source(self):
        """Same offset + different source -> do not carry, flag for review."""
        _write_csv(self._old_path(), [
            ["0x10@f.bin", "Hello", "Bonjour"],
        ])
        _write_csv(self._new_path(), [
            ["0x10@f.bin", "Hello World", "Hello World"],
        ])
        result, rows = merge_translations(self._old_path(), self._new_path())
        self.assertEqual(len(result.modified_source), 1)
        self.assertEqual(result.carried, 0)
        self.assertEqual(rows[0]["target"], "Hello World")
        # Check modified_source details
        offset, old_src, new_src, old_tgt = result.modified_source[0]
        self.assertEqual(offset, "0x10")
        self.assertEqual(old_src, "Hello")
        self.assertEqual(new_src, "Hello World")
        self.assertEqual(old_tgt, "Bonjour")

    def test_new_string(self):
        """Offset only in new file -> new string, untranslated."""
        _write_csv(self._old_path(), [
            ["0x10@f.bin", "Hello", "Bonjour"],
        ])
        _write_csv(self._new_path(), [
            ["0x10@f.bin", "Hello", "Hello"],
            ["0x20@f.bin", "New text", "New text"],
        ])
        result, rows = merge_translations(self._old_path(), self._new_path())
        self.assertEqual(result.new_strings, 1)
        self.assertEqual(rows[1]["target"], "New text")

    def test_removed_string(self):
        """Offset only in old file -> removed."""
        _write_csv(self._old_path(), [
            ["0x10@f.bin", "Hello", "Bonjour"],
            ["0x20@f.bin", "Old", "Ancien"],
        ])
        _write_csv(self._new_path(), [
            ["0x10@f.bin", "Hello", "Hello"],
        ])
        result, rows = merge_translations(self._old_path(), self._new_path())
        self.assertEqual(result.removed, 1)
        self.assertEqual(len(rows), 1)

    def test_mixed_scenario(self):
        """All categories at once."""
        _write_csv(self._old_path(), [
            ["0x10@f.bin", "Carried", "Porté"],           # carry
            ["0x20@f.bin", "Unchanged", "Unchanged"],      # unchanged
            ["0x30@f.bin", "Modified", "Modifié"],         # modified source
            ["0x40@f.bin", "Removed", "Supprimé"],         # removed
        ])
        _write_csv(self._new_path(), [
            ["0x10@f.bin", "Carried", "Carried"],          # same source
            ["0x20@f.bin", "Unchanged", "Unchanged"],      # same, no translation
            ["0x30@f.bin", "Modified v2", "Modified v2"],  # source changed
            ["0x50@f.bin", "Brand new", "Brand new"],      # new
        ])
        result, rows = merge_translations(self._old_path(), self._new_path())
        self.assertEqual(result.carried, 1)
        self.assertEqual(result.unchanged, 1)
        self.assertEqual(len(result.modified_source), 1)
        self.assertEqual(result.new_strings, 1)
        self.assertEqual(result.removed, 1)
        self.assertEqual(len(rows), 4)

        # Verify carried translation
        self.assertEqual(rows[0]["target"], "Porté")
        # Verify unchanged
        self.assertEqual(rows[1]["target"], "Unchanged")
        # Verify modified source not carried
        self.assertEqual(rows[2]["target"], "Modified v2")
        # Verify new string
        self.assertEqual(rows[3]["target"], "Brand new")

    def test_empty_old_csv(self):
        """Empty old file means everything is new."""
        _write_csv(self._old_path(), [])
        _write_csv(self._new_path(), [
            ["0x10@f.bin", "Hello", "Hello"],
        ])
        result, rows = merge_translations(self._old_path(), self._new_path())
        self.assertEqual(result.new_strings, 1)
        self.assertEqual(result.carried, 0)
        self.assertEqual(len(rows), 1)

    def test_empty_new_csv(self):
        """Empty new file means everything is removed."""
        _write_csv(self._old_path(), [
            ["0x10@f.bin", "Hello", "Bonjour"],
        ])
        _write_csv(self._new_path(), [])
        result, rows = merge_translations(self._old_path(), self._new_path())
        self.assertEqual(result.removed, 1)
        self.assertEqual(len(rows), 0)

    def test_json_merge(self):
        """JSON-to-JSON merge works the same as CSV."""
        old_path = self._old_path(".json")
        new_path = self._new_path(".json")
        _write_json(old_path, [
            ["0x10@f.bin", "Hello", "Bonjour"],
            ["0x20@f.bin", "World", "World"],
        ])
        _write_json(new_path, [
            ["0x10@f.bin", "Hello", "Hello"],
            ["0x20@f.bin", "World", "World"],
            ["0x30@f.bin", "New", "New"],
        ])
        result, rows = merge_translations(old_path, new_path)
        self.assertEqual(result.carried, 1)
        self.assertEqual(result.unchanged, 1)
        self.assertEqual(result.new_strings, 1)
        self.assertEqual(rows[0]["target"], "Bonjour")


class TestWriteMergedCSV(unittest.TestCase):
    """Tests for write_merged_csv."""

    def test_writes_valid_csv(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            rows = [
                {"location": "0x10@f.bin", "source": "Hello", "target": "Bonjour"},
                {"location": "0x20@f.bin", "source": "World", "target": "Monde"},
            ]
            count = write_merged_csv(rows, path)
            self.assertEqual(count, 2)

            csv_rows = _read_csv_rows(path)
            self.assertEqual(len(csv_rows), 2)
            self.assertEqual(csv_rows[0], ["0x10@f.bin", "Hello", "Bonjour"])
            self.assertEqual(csv_rows[1], ["0x20@f.bin", "World", "Monde"])
        finally:
            os.unlink(path)

    def test_csv_has_header(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            write_merged_csv([], path)
            with open(path, "r", newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
            self.assertEqual(header, ["location", "source", "target"])
        finally:
            os.unlink(path)

    def test_output_compatible_with_csv_to_bin(self):
        """Output CSV should be loadable by import_data (location, source, target format)."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            rows = [{"location": "0x64@mhfdat.bin", "source": "Test", "target": "Traduit"}]
            write_merged_csv(rows, path)

            csv_rows = _read_csv_rows(path)
            self.assertEqual(csv_rows[0][0], "0x64@mhfdat.bin")
            self.assertEqual(csv_rows[0][2], "Traduit")
        finally:
            os.unlink(path)


class TestWriteMergedJSON(unittest.TestCase):
    """Tests for write_merged_json."""

    def test_writes_valid_json(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            rows = [
                {"location": "0x10@f.bin", "source": "Hello", "target": "Bonjour"},
            ]
            count = write_merged_json(rows, path, source_file="test.bin")
            self.assertEqual(count, 1)

            strings = _read_json_strings(path)
            self.assertEqual(len(strings), 1)
            self.assertEqual(strings[0]["target"], "Bonjour")
        finally:
            os.unlink(path)

    def test_json_has_metadata(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            write_merged_json([], path, source_file="data.bin")
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertIn("metadata", data)
            self.assertEqual(data["metadata"]["source_file"], "data.bin")
        finally:
            os.unlink(path)


class TestWriteMergedAutoDetect(unittest.TestCase):
    """Tests for write_merged auto-detection."""

    def test_detects_csv(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            rows = [{"location": "0x10@f.bin", "source": "A", "target": "B"}]
            write_merged(rows, path)
            csv_rows = _read_csv_rows(path)
            self.assertEqual(len(csv_rows), 1)
        finally:
            os.unlink(path)

    def test_detects_json(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            rows = [{"location": "0x10@f.bin", "source": "A", "target": "B"}]
            write_merged(rows, path)
            strings = _read_json_strings(path)
            self.assertEqual(len(strings), 1)
        finally:
            os.unlink(path)


class TestFormatMergeReport(unittest.TestCase):
    """Tests for format_merge_report."""

    def test_basic_report(self):
        result = MergeResult(
            old_file="old.csv",
            new_file="new.csv",
            carried=5,
            unchanged=10,
            modified_source=[],
            new_strings=2,
            removed=1,
        )
        report = format_merge_report(result)
        self.assertIn("old.csv", report)
        self.assertIn("new.csv", report)
        self.assertIn("5", report)
        self.assertIn("10", report)
        self.assertIn("2", report)
        self.assertIn("1", report)
        self.assertIn("17 strings", report)

    def test_report_with_modified_source(self):
        result = MergeResult(
            old_file="old.csv",
            new_file="new.csv",
            carried=0,
            unchanged=0,
            modified_source=[("0x10", "Old text", "New text", "Ancien texte")],
            new_strings=0,
            removed=0,
        )
        report = format_merge_report(result)
        self.assertIn("Modified source strings (1)", report)
        self.assertIn("0x10", report)
        self.assertIn("Old text", report)
        self.assertIn("New text", report)
        self.assertIn("Ancien texte", report)
        self.assertIn("NOT carried", report)

    def test_report_no_modified(self):
        result = MergeResult(
            old_file="a.csv",
            new_file="b.csv",
            carried=3,
            unchanged=7,
            modified_source=[],
            new_strings=0,
            removed=0,
        )
        report = format_merge_report(result)
        self.assertNotIn("Modified source strings", report)


class TestEndToEndMerge(unittest.TestCase):
    """End-to-end tests for merge workflow."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_csv_round_trip(self):
        """Full workflow: merge CSVs and write output."""
        old_path = os.path.join(self.tmpdir, "old.csv")
        new_path = os.path.join(self.tmpdir, "new.csv")
        out_path = os.path.join(self.tmpdir, "merged.csv")

        _write_csv(old_path, [
            ["0x10@mhfdat.bin", "Sword", "Épée"],
            ["0x20@mhfdat.bin", "Shield", "Shield"],
            ["0x30@mhfdat.bin", "Bow", "Arc"],
        ])
        _write_csv(new_path, [
            ["0x10@mhfdat.bin", "Sword", "Sword"],
            ["0x20@mhfdat.bin", "Shield", "Shield"],
            ["0x30@mhfdat.bin", "Bow v2", "Bow v2"],
            ["0x40@mhfdat.bin", "Lance", "Lance"],
        ])

        result, rows = merge_translations(old_path, new_path)
        count = write_merged_csv(rows, out_path)

        self.assertEqual(count, 4)
        self.assertEqual(result.carried, 1)       # Sword -> Épée
        self.assertEqual(result.unchanged, 1)      # Shield
        self.assertEqual(len(result.modified_source), 1)  # Bow changed
        self.assertEqual(result.new_strings, 1)    # Lance
        self.assertEqual(result.removed, 0)

        csv_rows = _read_csv_rows(out_path)
        self.assertEqual(csv_rows[0][2], "Épée")       # carried
        self.assertEqual(csv_rows[1][2], "Shield")      # unchanged
        self.assertEqual(csv_rows[2][2], "Bow v2")      # not carried
        self.assertEqual(csv_rows[3][2], "Lance")       # new

    def test_json_round_trip(self):
        """Full workflow: merge JSONs and write output."""
        old_path = os.path.join(self.tmpdir, "old.json")
        new_path = os.path.join(self.tmpdir, "new.json")
        out_path = os.path.join(self.tmpdir, "merged.json")

        _write_json(old_path, [
            ["0x10@mhfdat.bin", "Sword", "Épée"],
            ["0x20@mhfdat.bin", "Shield", "Shield"],
        ])
        _write_json(new_path, [
            ["0x10@mhfdat.bin", "Sword", "Sword"],
            ["0x20@mhfdat.bin", "Shield", "Shield"],
            ["0x30@mhfdat.bin", "Lance", "Lance"],
        ])

        result, rows = merge_translations(old_path, new_path)
        count = write_merged(rows, out_path, source_file="mhfdat.bin")

        self.assertEqual(count, 3)
        self.assertEqual(result.carried, 1)

        strings = _read_json_strings(out_path)
        self.assertEqual(strings[0]["target"], "Épée")
        self.assertEqual(strings[2]["target"], "Lance")


if __name__ == "__main__":
    unittest.main()
