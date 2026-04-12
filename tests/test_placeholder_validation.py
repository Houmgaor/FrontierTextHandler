"""
Tests for the tier-2 placeholder validator.

Covers the pure function (:func:`validate_placeholders`), the
stateful collector (:class:`PlaceholderValidator`), the standalone
file-level validator (:func:`validate_translation_file`), and the
inline hooks inside the CSV/JSON importers — both the default
"warn and proceed" path and the ``strict_placeholders=True`` hard-
fail path.
"""
import csv
import json
import logging
import os
import struct
import tempfile
import unittest

from src.common import GAME_ENCODING, JOIN_MARKER
from src.placeholder_validation import (
    PlaceholderIssue,
    PlaceholderValidator,
    PlaceholderValidationError,
    validate_placeholders,
    validate_translation_file,
)
from src.import_data import (
    get_new_strings,
    get_new_strings_from_json,
    get_new_strings_indexed,
    get_new_strings_auto,
)


class TestValidatePlaceholdersPureFunction(unittest.TestCase):
    """Unit tests for the pure :func:`validate_placeholders` function."""

    def test_identical_strings_no_issues(self):
        self.assertEqual(validate_placeholders("hello", "hello"), [])

    def test_no_placeholders_is_fine(self):
        self.assertEqual(
            validate_placeholders("plain source", "plain target"),
            [],
        )

    def test_matching_single_placeholder(self):
        self.assertEqual(
            validate_placeholders(
                "Press {K012} to open", "Appuyez sur {K012} pour ouvrir"
            ),
            [],
        )

    def test_matching_multiple_placeholders(self):
        self.assertEqual(
            validate_placeholders(
                "{c05}Warning{/c}: {i131} low HP",
                "{c05}Attention{/c} : {i131} PV bas",
            ),
            [],
        )

    def test_dropped_color_code(self):
        issues = validate_placeholders(
            "{c05}Warning{/c}: low HP",
            "Attention : PV bas",
        )
        self.assertEqual(len(issues), 2)
        markers = {i.marker for i in issues}
        self.assertEqual(markers, {"{c05}", "{/c}"})
        for i in issues:
            self.assertTrue(i.missing)
            self.assertEqual(i.target_count, 0)
            self.assertEqual(i.source_count, 1)

    def test_dropped_keybind(self):
        issues = validate_placeholders(
            "Press {K012} to open the map",
            "Appuyez pour ouvrir la carte",
        )
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].marker, "{K012}")
        self.assertTrue(issues[0].missing)

    def test_typo_in_placeholder_number(self):
        """A typo produces one 'missing' and one 'extra' issue."""
        issues = validate_placeholders(
            "Open with {K012}",
            "Ouvrir avec {K013}",
        )
        self.assertEqual(len(issues), 2)
        markers = sorted(i.marker for i in issues)
        self.assertEqual(markers, ["{K012}", "{K013}"])
        missing = next(i for i in issues if i.marker == "{K012}")
        extra = next(i for i in issues if i.marker == "{K013}")
        self.assertTrue(missing.missing)
        self.assertTrue(extra.extra)

    def test_dropped_join_marker(self):
        """Dropping a ``{j}`` is caught at validation time, before the
        grouped-entry sub-string count check would fire much later."""
        issues = validate_placeholders(
            "Title{j}Subtitle{j}Body",
            "Title + Body",
        )
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].marker, "{j}")
        self.assertEqual(issues[0].source_count, 2)
        self.assertEqual(issues[0].target_count, 0)

    def test_count_mismatch(self):
        """Duplicating a placeholder is flagged even if the name matches."""
        issues = validate_placeholders(
            "Press {K012}",
            "Press {K012}{K012}",
        )
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue.marker, "{K012}")
        self.assertEqual(issue.source_count, 1)
        self.assertEqual(issue.target_count, 2)
        self.assertTrue(issue.extra)
        self.assertFalse(issue.missing)

    def test_unknown_placeholder_added(self):
        """A made-up placeholder in target with no source counterpart is flagged."""
        issues = validate_placeholders(
            "plain source",
            "plain target with {foo}",
        )
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].marker, "{foo}")
        self.assertTrue(issues[0].extra)

    def test_reordering_is_fine(self):
        """Reordering is legitimate translator freedom and must not flag."""
        self.assertEqual(
            validate_placeholders(
                "{c05}Level {i131}{/c} reached",
                "Niveau {i131} {c05}atteint{/c}",
            ),
            [],
        )

    def test_issue_describe_human_readable(self):
        issue = PlaceholderIssue("{K012}", 1, 0)
        self.assertIn("missing", issue.describe())
        self.assertIn("{K012}", issue.describe())

    def test_brace_with_space_is_not_a_marker(self):
        """``{Not A Marker}`` contains spaces → not matched by the regex."""
        # source has plain text with braces-and-spaces, target drops it —
        # no issue because neither cell has a matching brace token.
        self.assertEqual(
            validate_placeholders(
                "Literal {Not A Marker} text", "Literal text"
            ),
            [],
        )


class TestPlaceholderValidatorCollector(unittest.TestCase):
    """Tests for the stateful :class:`PlaceholderValidator` collector."""

    def test_clean_rows_produce_no_issues(self):
        v = PlaceholderValidator()
        v.check("row 1", "hello {K01}", "bonjour {K01}")
        v.check("row 2", "plain", "simple")
        self.assertEqual(v.issue_count, 0)

    def test_collects_issues_across_rows(self):
        v = PlaceholderValidator()
        v.check("row 1", "fine", "fine")
        v.check("row 2", "{c05}bad{/c}", "bad")
        v.check("row 3", "{K012}", "")
        self.assertEqual(v.issue_count, 2)
        row_ids = [row_id for row_id, _ in v.rows]
        self.assertEqual(row_ids, ["row 2", "row 3"])

    def test_strict_mode_raises_immediately(self):
        v = PlaceholderValidator(strict=True)
        v.check("row 1", "fine", "fine")  # ok
        with self.assertRaises(PlaceholderValidationError) as ctx:
            v.check("row 2", "{c05}x{/c}", "x")
        self.assertIn("row 2", str(ctx.exception))
        self.assertEqual(ctx.exception.row_id, "row 2")
        self.assertEqual(len(ctx.exception.issues), 2)

    def test_log_summary_is_noop_when_clean(self):
        v = PlaceholderValidator()
        with self.assertLogs("src.placeholder_validation", level="WARNING") as ctx:
            v.check("row 1", "a", "a")
            # Force at least one record so assertLogs has something
            # to compare against when the summary is a no-op.
            logging.getLogger("src.placeholder_validation").warning("probe")
            v.log_summary("dummy.csv")
        self.assertTrue(
            all("Placeholder validation" not in m for m in ctx.output),
            f"Unexpected placeholder warning: {ctx.output}",
        )

    def test_log_summary_emits_warning_when_issues(self):
        v = PlaceholderValidator()
        v.check("row 1", "{K01}", "")
        v.check("row 2", "{j}a{j}b", "a b")
        with self.assertLogs(
            "src.placeholder_validation", level="WARNING"
        ) as ctx:
            v.log_summary("my.csv")
        joined = "\n".join(ctx.output)
        self.assertIn("Placeholder validation", joined)
        self.assertIn("2 row(s)", joined)
        self.assertIn("my.csv", joined)
        self.assertIn("row 1", joined)
        self.assertIn("row 2", joined)

    def test_log_summary_truncates_beyond_max_detailed(self):
        v = PlaceholderValidator()
        for i in range(10):
            v.check(f"row {i}", "{K01}", "")
        with self.assertLogs(
            "src.placeholder_validation", level="WARNING"
        ) as ctx:
            v.log_summary("many.csv", max_detailed=3)
        joined = "\n".join(ctx.output)
        self.assertIn("10 row(s)", joined)
        self.assertIn("and 7 more", joined)


class TestValidateTranslationFileCSV(unittest.TestCase):
    """Tests for :func:`validate_translation_file` on CSV inputs."""

    def _write_csv(self, rows: list[list[str]], header: list[str]) -> str:
        fd, path = tempfile.mkstemp(suffix=".csv")
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(rows)
        self.addCleanup(os.unlink, path)
        return path

    def test_clean_csv_has_no_issues(self):
        path = self._write_csv(
            [
                ["0", "Press {K012}", "Appuyez sur {K012}"],
                ["1", "{c05}Warning{/c}", "{c05}Attention{/c}"],
            ],
            ["index", "source", "target"],
        )
        v = validate_translation_file(path)
        self.assertEqual(v.issue_count, 0)

    def test_index_keyed_csv_flags_missing_marker(self):
        path = self._write_csv(
            [
                ["0", "Press {K012} to open", "Appuyez pour ouvrir"],
                ["1", "fine", "fine"],
            ],
            ["index", "source", "target"],
        )
        v = validate_translation_file(path)
        self.assertEqual(v.issue_count, 1)
        self.assertEqual(v.rows[0][0], "line 2")
        self.assertEqual(v.rows[0][1][0].marker, "{K012}")

    def test_legacy_offset_csv_is_also_linted(self):
        path = self._write_csv(
            [
                ["0x10@test.bin", "{c05}a{/c}", "a"],
            ],
            ["location", "source", "target"],
        )
        v = validate_translation_file(path)
        self.assertEqual(v.issue_count, 1)
        markers = {i.marker for i in v.rows[0][1]}
        self.assertEqual(markers, {"{c05}", "{/c}"})

    def test_strict_mode_raises_at_first_issue(self):
        path = self._write_csv(
            [
                ["0", "clean", "clean"],
                ["1", "{K012}", "missing placeholder"],
                ["2", "{K013}", "also missing"],
            ],
            ["index", "source", "target"],
        )
        with self.assertRaises(PlaceholderValidationError) as ctx:
            validate_translation_file(path, strict=True)
        self.assertEqual(ctx.exception.row_id, "line 3")

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            validate_translation_file("/no/such/file.csv")


class TestValidateTranslationFileJSON(unittest.TestCase):
    """Tests for :func:`validate_translation_file` on JSON inputs."""

    def _write_json(self, strings: list[dict]) -> str:
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"metadata": {"source_file": "x.bin"}, "strings": strings}, f)
        self.addCleanup(os.unlink, path)
        return path

    def test_clean_json_has_no_issues(self):
        path = self._write_json(
            [
                {"index": 0, "source": "Press {K01}", "target": "Appuyez {K01}"},
                {"index": 1, "source": "clean", "target": "clean"},
            ]
        )
        v = validate_translation_file(path)
        self.assertEqual(v.issue_count, 0)

    def test_json_flags_dropped_marker(self):
        path = self._write_json(
            [
                {"index": 0, "source": "{j}a{j}b", "target": "ab"},
                {"index": 1, "source": "{K012}", "target": "{K012}"},
            ]
        )
        v = validate_translation_file(path)
        self.assertEqual(v.issue_count, 1)
        self.assertEqual(v.rows[0][0], "entry 0")

    def test_json_without_strings_key_raises(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"metadata": {}}, f)
        self.addCleanup(os.unlink, path)
        with self.assertRaises(ValueError):
            validate_translation_file(path)


class TestInlineHookInReaders(unittest.TestCase):
    """Confirm the importers run the validator on every row."""

    def _write_csv(self, rows: list[list[str]], header: list[str]) -> str:
        fd, path = tempfile.mkstemp(suffix=".csv")
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(rows)
        self.addCleanup(os.unlink, path)
        return path

    def test_get_new_strings_warns_on_mismatch(self):
        path = self._write_csv(
            [
                ["0x10@f.bin", "Press {K012}", "Appuyez pour ouvrir"],
            ],
            ["location", "source", "target"],
        )
        with self.assertLogs(
            "src.placeholder_validation", level="WARNING"
        ) as ctx:
            result = get_new_strings(path)
        # Warning surfaced, but the row still came through (default
        # non-strict mode is lenient).
        self.assertEqual(len(result), 1)
        self.assertIn("Placeholder validation", "\n".join(ctx.output))

    def test_get_new_strings_strict_raises(self):
        path = self._write_csv(
            [
                ["0x10@f.bin", "Press {K012}", "Appuyez"],
            ],
            ["location", "source", "target"],
        )
        with self.assertRaises(PlaceholderValidationError):
            get_new_strings(path, strict_placeholders=True)

    def test_get_new_strings_indexed_strict_raises(self):
        path = self._write_csv(
            [
                ["0", "{c05}bad{/c}", "bad"],
            ],
            ["index", "source", "target"],
        )
        with self.assertRaises(PlaceholderValidationError):
            get_new_strings_indexed(path, strict_placeholders=True)

    def test_get_new_strings_auto_threads_strict(self):
        path = self._write_csv(
            [
                ["0x10@f.bin", "{K012}", ""],
            ],
            ["location", "source", "target"],
        )
        with self.assertRaises(PlaceholderValidationError):
            get_new_strings_auto(path, strict_placeholders=True)

    def test_get_new_strings_from_json_strict_raises(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "metadata": {"source_file": "f.bin"},
                    "strings": [
                        {
                            "location": "0x10@f.bin",
                            "source": "{K012}",
                            "target": "missing placeholder",
                        }
                    ],
                },
                f,
            )
        self.addCleanup(os.unlink, path)
        with self.assertRaises(PlaceholderValidationError):
            get_new_strings_from_json(path, strict_placeholders=True)


class TestInlineHookRealRoundtrip(unittest.TestCase):
    """
    End-to-end: extract a grouped section → edit a CSV dropping a
    ``{j}`` marker → import with strict mode → expect a hard failure
    before any binary write happens.
    """

    def test_strict_import_aborts_on_dropped_join_marker(self):
        from src.pointer_tables import read_multi_pointer_entries
        from src.binary_file import BinaryFile
        from src.export import export_as_csv
        from src.import_data import import_from_csv

        # Tiny 2-sub grouped entry binary
        str_a = "Hello".encode(GAME_ENCODING) + b"\x00"
        str_b = "World".encode(GAME_ENCODING) + b"\x00"
        strings_start = 16
        data = bytearray()
        data.extend(struct.pack("<I", strings_start))
        data.extend(struct.pack("<I", strings_start + len(str_a)))
        data.extend(struct.pack("<I", 0))
        data.extend(struct.pack("<I", 0))
        data.extend(str_a + str_b)
        bfile = BinaryFile.from_bytes(bytes(data))
        entries = read_multi_pointer_entries(bfile, 0, 2)

        with tempfile.TemporaryDirectory() as tmpdir:
            bin_path = os.path.join(tmpdir, "source.bin")
            with open(bin_path, "wb") as f:
                f.write(bytes(data))
            csv_path = os.path.join(tmpdir, "edited.csv")
            # Export with legacy-offset so the importer round-trips
            # through the simple append-style path; the strict check
            # runs the same way on both shapes.
            export_as_csv(
                entries, csv_path, "source.bin", with_index=False,
            )

            # Corrupt the target cell: drop the {j} marker
            rows = []
            with open(csv_path, encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
                for row in reader:
                    rows.append(row)
            self.assertIn(JOIN_MARKER, rows[0][1])
            rows[0][2] = rows[0][1].replace(JOIN_MARKER, " ")

            edited = os.path.join(tmpdir, "bad.csv")
            with open(edited, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(header)
                writer.writerows(rows)

            # Strict mode should abort before touching any binary.
            out = os.path.join(tmpdir, "out.bin")
            with self.assertRaises(PlaceholderValidationError):
                import_from_csv(
                    edited, bin_path, output_path=out,
                    strict_placeholders=True,
                )
            self.assertFalse(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
