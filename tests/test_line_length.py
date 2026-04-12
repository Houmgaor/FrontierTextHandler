"""Tests for the line-length validation module."""
import csv
import json
import os
import tempfile
import unittest

from src.line_length import (
    display_width,
    measure_section_limits,
    validate_line_length,
    LineLengthIssue,
    SubCountIssue,
    LineLengthValidator,
    LineLengthValidationError,
    validate_translation_file_line_lengths,
)


class TestDisplayWidth(unittest.TestCase):
    """Tests for the display_width function."""

    def test_ascii(self):
        self.assertEqual(display_width("hello"), 5)

    def test_cjk(self):
        # Each CJK char = 2 cells
        self.assertEqual(display_width("日本語"), 6)

    def test_mixed(self):
        # "AB" = 2, "漢字" = 4 → 6
        self.assertEqual(display_width("AB漢字"), 6)

    def test_empty(self):
        self.assertEqual(display_width(""), 0)

    def test_placeholders_stripped(self):
        # Placeholders should not count toward width
        self.assertEqual(display_width("{c05}Hello{/c}"), 5)
        self.assertEqual(display_width("{K012}Press"), 5)
        self.assertEqual(display_width("{j}"), 0)
        self.assertEqual(display_width("{i131}"), 0)

    def test_fullwidth_latin(self):
        # Fullwidth Latin letters are W category → 2 cells each
        self.assertEqual(display_width("Ａ"), 2)

    def test_placeholder_among_cjk(self):
        # "装備" = 4, placeholder stripped, "名" = 2 → 6
        self.assertEqual(display_width("装備{c05}名"), 6)


class TestMeasureSectionLimits(unittest.TestCase):
    """Tests for measure_section_limits."""

    def test_simple_entries(self):
        entries = [
            {"text": "short"},
            {"text": "a longer string here"},
            {"text": "mid"},
        ]
        result = measure_section_limits(entries)
        self.assertEqual(result["max_display_width"], 20)
        self.assertEqual(result["max_sub_count"], 1)

    def test_grouped_entries(self):
        entries = [
            {"text": "Title{j}Objective{j}Extra"},
            {"text": "Short{j}OK"},
        ]
        result = measure_section_limits(entries)
        # "Objective" = 9 is the widest sub-string
        self.assertEqual(result["max_display_width"], 9)
        self.assertEqual(result["max_sub_count"], 3)

    def test_cjk_entries(self):
        entries = [
            {"text": "武器名"},  # 3 CJK chars = 6 cells
            {"text": "a"},      # 1 cell
        ]
        result = measure_section_limits(entries)
        self.assertEqual(result["max_display_width"], 6)

    def test_empty(self):
        result = measure_section_limits([])
        self.assertEqual(result["max_display_width"], 0)
        self.assertEqual(result["max_sub_count"], 0)

    def test_placeholders_excluded(self):
        entries = [
            {"text": "{c05}AB{/c}"},  # only "AB" = 2 cells
        ]
        result = measure_section_limits(entries)
        self.assertEqual(result["max_display_width"], 2)


class TestValidateLineLength(unittest.TestCase):
    """Tests for the validate_line_length function."""

    def test_within_limit(self):
        issues = validate_line_length("Hello", max_display_width=10)
        self.assertEqual(issues, [])

    def test_exceeds_limit(self):
        issues = validate_line_length("Hello World!", max_display_width=5)
        self.assertEqual(len(issues), 1)
        self.assertIsInstance(issues[0], LineLengthIssue)
        self.assertEqual(issues[0].width, 12)
        self.assertEqual(issues[0].max_width, 5)

    def test_margin(self):
        # "Hello" = 5 cells, limit 4 × 1.5 = 6 → OK
        issues = validate_line_length("Hello", max_display_width=4, margin=1.5)
        self.assertEqual(issues, [])

    def test_sub_count_exceeded(self):
        issues = validate_line_length(
            "A{j}B{j}C", max_display_width=100, max_sub_count=2,
        )
        self.assertEqual(len(issues), 1)
        self.assertIsInstance(issues[0], SubCountIssue)
        self.assertEqual(issues[0].count, 3)
        self.assertEqual(issues[0].max_count, 2)

    def test_both_violations(self):
        # 3 subs (limit 2) + each sub "ABCDEF" = 6 (limit 3)
        issues = validate_line_length(
            "ABCDEF{j}ABCDEF{j}ABCDEF",
            max_display_width=3,
            max_sub_count=2,
        )
        # 1 SubCountIssue + 3 LineLengthIssue
        self.assertEqual(len(issues), 4)

    def test_exact_limit(self):
        issues = validate_line_length("Hello", max_display_width=5)
        self.assertEqual(issues, [])

    def test_grouped_per_sub_check(self):
        # "Short" = 5, "This is longer" = 14; limit 10
        issues = validate_line_length(
            "Short{j}This is longer", max_display_width=10,
        )
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].sub_index, 1)
        self.assertEqual(issues[0].width, 14)


class TestLineLengthValidator(unittest.TestCase):
    """Tests for the stateful LineLengthValidator collector."""

    def test_no_limits(self):
        v = LineLengthValidator()
        v.check("row 1", "anything goes")
        self.assertEqual(v.issue_count, 0)

    def test_collects_issues(self):
        v = LineLengthValidator(max_display_width=5)
        v.check("row 1", "OK")
        v.check("row 2", "This exceeds the limit")
        self.assertEqual(v.issue_count, 1)

    def test_strict_raises(self):
        v = LineLengthValidator(max_display_width=3, strict=True)
        with self.assertRaises(LineLengthValidationError):
            v.check("row 1", "Too long")

    def test_log_summary(self):
        v = LineLengthValidator(max_display_width=3)
        v.check("row 1", "ABCDEF")
        v.check("row 2", "GHIJKL")
        # Should not raise — just exercises the logging path
        v.log_summary("test.csv")
        self.assertEqual(v.issue_count, 2)

    def test_margin(self):
        v = LineLengthValidator(max_display_width=5, margin=2.0)
        v.check("row 1", "Hello World")  # 11 > 10 → violation
        self.assertEqual(v.issue_count, 1)
        v2 = LineLengthValidator(max_display_width=5, margin=2.0)
        v2.check("row 1", "HelloWorld")  # 10 = 10 → OK
        self.assertEqual(v2.issue_count, 0)


class TestValidateTranslationFile(unittest.TestCase):
    """Tests for the standalone file validator."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # Create a minimal headers.json with limits
        self.headers_path = os.path.join(self.tmpdir, "headers.json")
        headers = {
            "test": {
                "section": {
                    "begin_pointer": "0x10",
                    "next_field_pointer": "0x14",
                    "max_display_width": 10,
                    "max_sub_count": 2,
                }
            }
        }
        with open(self.headers_path, "w") as f:
            json.dump(headers, f)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_csv_all_ok(self):
        csv_path = os.path.join(self.tmpdir, "test-section.csv")
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["index", "source", "target"])
            w.writerow([0, "Original", "Translat"])  # 8 <= 10
        v = validate_translation_file_line_lengths(
            csv_path, headers_path=self.headers_path,
        )
        self.assertEqual(v.issue_count, 0)

    def test_csv_violation(self):
        csv_path = os.path.join(self.tmpdir, "test-section.csv")
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["index", "source", "target"])
            w.writerow([0, "Short", "This is way too long for the limit"])
        v = validate_translation_file_line_lengths(
            csv_path, headers_path=self.headers_path,
        )
        self.assertEqual(v.issue_count, 1)

    def test_json_violation(self):
        json_path = os.path.join(self.tmpdir, "test-section.json")
        data = {
            "metadata": {"xpath": "test/section"},
            "strings": [
                {"index": 0, "source": "Short",
                 "target": "This is way too long for the limit"},
            ],
        }
        with open(json_path, "w") as f:
            json.dump(data, f)
        v = validate_translation_file_line_lengths(
            json_path, headers_path=self.headers_path,
            xpath="test/section",
        )
        self.assertEqual(v.issue_count, 1)

    def test_skips_untranslated_rows(self):
        csv_path = os.path.join(self.tmpdir, "test-section.csv")
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["index", "source", "target"])
            # source == target → untranslated, skip
            w.writerow([0, "Very long original source text", "Very long original source text"])
        v = validate_translation_file_line_lengths(
            csv_path, headers_path=self.headers_path,
        )
        self.assertEqual(v.issue_count, 0)

    def test_margin_override(self):
        csv_path = os.path.join(self.tmpdir, "test-section.csv")
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["index", "source", "target"])
            w.writerow([0, "Short", "Twelve chars"])  # 12 > 10 but 12 <= 15
        # margin 1.5 → effective limit 15
        v = validate_translation_file_line_lengths(
            csv_path, headers_path=self.headers_path, margin=1.5,
        )
        self.assertEqual(v.issue_count, 0)

    def test_no_limits_in_config(self):
        headers = {
            "test": {
                "nolimit": {
                    "begin_pointer": "0x10",
                    "next_field_pointer": "0x14",
                }
            }
        }
        with open(self.headers_path, "w") as f:
            json.dump(headers, f)
        csv_path = os.path.join(self.tmpdir, "test-nolimit.csv")
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["index", "source", "target"])
            w.writerow([0, "Short", "Any length is fine without limits"])
        v = validate_translation_file_line_lengths(
            csv_path, headers_path=self.headers_path,
        )
        self.assertEqual(v.issue_count, 0)

    def test_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            validate_translation_file_line_lengths(
                "/nonexistent.csv", headers_path=self.headers_path,
            )

    def test_no_xpath_raises(self):
        csv_path = os.path.join(self.tmpdir, "mystery.csv")
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["index", "source", "target"])
        with self.assertRaises(ValueError):
            validate_translation_file_line_lengths(
                csv_path, headers_path=self.headers_path,
            )


class TestIssueDescriptions(unittest.TestCase):
    """Tests for issue describe() methods."""

    def test_line_length_describe(self):
        issue = LineLengthIssue(sub_index=1, width=15, max_width=10)
        desc = issue.describe()
        self.assertIn("15", desc)
        self.assertIn("10", desc)
        self.assertIn("sub-string 1", desc)

    def test_sub_count_describe(self):
        issue = SubCountIssue(count=5, max_count=3)
        desc = issue.describe()
        self.assertIn("5", desc)
        self.assertIn("3", desc)


if __name__ == "__main__":
    unittest.main()
