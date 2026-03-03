"""Tests for src/transform.py — ReFrontier format conversion."""

import csv
import os
import tempfile
import unittest

from src.common import GAME_ENCODING, REFRONTIER_REPLACEMENTS
from src.transform import import_from_refrontier, refrontier_to_csv


class TestImportFromRefrontier(unittest.TestCase):
    """Test import_from_refrontier."""

    def _write_refrontier(self, rows: list[list[str]]) -> str:
        """Write a ReFrontier-format TSV file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.unlink, path)

        with open(path, "w", newline="\n", encoding=GAME_ENCODING) as f:
            writer = csv.writer(f, delimiter="\t", quoting=csv.QUOTE_MINIMAL)
            writer.writerow(["Offset", "Hash", "JString"])
            for row in rows:
                writer.writerow(row)
        return path

    def test_basic_import(self):
        path = self._write_refrontier([["100", "12345", "Hello"]])
        results = list(import_from_refrontier(path))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["offset"], 100)
        self.assertEqual(results[0]["text"], "Hello")

    def test_multiple_rows(self):
        path = self._write_refrontier([
            ["100", "111", "Alpha"],
            ["200", "222", "Beta"],
            ["300", "333", "Gamma"],
        ])
        results = list(import_from_refrontier(path))
        self.assertEqual(len(results), 3)
        self.assertEqual(results[2]["text"], "Gamma")

    def test_tab_escape(self):
        path = self._write_refrontier([["100", "111", "A<TAB>B"]])
        results = list(import_from_refrontier(path))
        self.assertEqual(results[0]["text"], "A\tB")

    def test_cline_escape(self):
        path = self._write_refrontier([["100", "111", "Line1<CLINE>Line2"]])
        results = list(import_from_refrontier(path))
        self.assertEqual(results[0]["text"], "Line1\r\nLine2")

    def test_nline_escape(self):
        path = self._write_refrontier([["100", "111", "A<NLINE>B"]])
        results = list(import_from_refrontier(path))
        self.assertEqual(results[0]["text"], "A\nB")

    def test_empty_file_raises(self):
        """File with only header but no data should produce empty iterator."""
        path = self._write_refrontier([])
        results = list(import_from_refrontier(path))
        self.assertEqual(results, [])

    def test_file_with_no_header_raises(self):
        """File with no content at all raises InterruptedError."""
        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.unlink, path)
        # Write empty file
        with open(path, "w", encoding=GAME_ENCODING) as f:
            pass
        with self.assertRaises(InterruptedError):
            list(import_from_refrontier(path))


class TestRefrontierToCsv(unittest.TestCase):
    """Test refrontier_to_csv."""

    def _write_refrontier(self, rows: list[list[str]]) -> str:
        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.unlink, path)

        with open(path, "w", newline="\n", encoding=GAME_ENCODING) as f:
            writer = csv.writer(f, delimiter="\t", quoting=csv.QUOTE_MINIMAL)
            writer.writerow(["Offset", "Hash", "JString"])
            for row in rows:
                writer.writerow(row)
        return path

    def test_basic_conversion(self):
        input_path = self._write_refrontier([
            ["100", "111", "Hello"],
            ["200", "222", "World"],
        ])
        fd, output_path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.unlink, output_path)

        count = refrontier_to_csv(input_path, output_path)
        self.assertEqual(count, 2)

        # Verify output CSV format
        with open(output_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            self.assertEqual(header, ["location", "source", "target"])
            rows = list(reader)
            self.assertEqual(len(rows), 2)

    def test_escape_sequences_converted(self):
        input_path = self._write_refrontier([
            ["100", "111", "A<TAB>B<NLINE>C"],
        ])
        fd, output_path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.unlink, output_path)

        refrontier_to_csv(input_path, output_path)

        with open(output_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            row = next(reader)
            # source and target should contain actual tab and newline
            self.assertIn("\t", row[1])
            self.assertIn("\n", row[1])

    def test_empty_input(self):
        input_path = self._write_refrontier([])
        fd, output_path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.unlink, output_path)

        count = refrontier_to_csv(input_path, output_path)
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
