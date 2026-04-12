"""
Validate that translations don't exceed the display width of original strings.

MH Frontier has fixed-width UI elements. Japanese strings fit because
they were designed for those widths. Translations that grow
significantly wider than their source risk overflowing text boxes.

The approach:

1. **Measure** — extract every section from the original binary, compute
   ``max_display_width`` (widest sub-string in cells) and
   ``max_sub_count`` (most ``{j}``-separated sub-strings) per section,
   and store those limits in ``headers.json``.
2. **Validate** — on import, warn when a translation sub-string exceeds
   ``max_display_width × margin`` or a grouped entry has more
   sub-strings than ``max_sub_count``.

Display width uses Unicode East Asian Width: fullwidth / wide characters
count as 2 cells, everything else as 1. Inline placeholders
(``{cNN}``, ``{/c}``, ``{j}``, ``{K…}``, ``{i…}``, ``{u…}``) are
stripped before measurement — they are runtime substitutions that don't
occupy fixed display space.
"""
import csv as _csv
import json as _json
import logging
import os
import re
import unicodedata
from dataclasses import dataclass, field
from typing import NamedTuple

from .placeholder_validation import _PLACEHOLDER_RE

logger = logging.getLogger(__name__)

# Characters with East Asian Width W or F render double-wide in the
# game's bitmap font.
_WIDE_CATEGORIES = frozenset({"W", "F"})


def display_width(text: str) -> int:
    """
    Compute display width in monospace cells.

    CJK / fullwidth characters count as 2, everything else as 1.
    Inline placeholders are stripped first — they don't occupy
    fixed glyph space on screen.
    """
    cleaned = _PLACEHOLDER_RE.sub("", text)
    total = 0
    for ch in cleaned:
        if unicodedata.east_asian_width(ch) in _WIDE_CATEGORIES:
            total += 2
        else:
            total += 1
    return total


def measure_section_limits(
    entries: list[dict],
) -> dict[str, int]:
    """
    Compute ``max_display_width`` and ``max_sub_count`` from extracted entries.

    Each entry has ``"text"`` (possibly containing ``{j}`` separators).
    Sub-strings are measured independently; the result is the maximum
    width across all sub-strings in all entries, and the maximum number
    of sub-strings in any single entry.

    :param entries: List of extractor entry dicts.
    :return: ``{"max_display_width": int, "max_sub_count": int}``
    """
    from .common import _JOIN_SPLIT_RE

    max_width = 0
    max_subs = 0
    for entry in entries:
        text = str(entry.get("text", ""))
        parts = _JOIN_SPLIT_RE.split(text)
        max_subs = max(max_subs, len(parts))
        for part in parts:
            w = display_width(part)
            if w > max_width:
                max_width = w
    return {"max_display_width": max_width, "max_sub_count": max_subs}


class LineLengthIssue(NamedTuple):
    """A single line-length violation."""

    sub_index: int
    width: int
    max_width: int

    @property
    def kind(self) -> str:
        return "width"

    def describe(self) -> str:
        return (
            f"sub-string {self.sub_index}: display width {self.width} "
            f"exceeds limit {self.max_width}"
        )


class SubCountIssue(NamedTuple):
    """A grouped entry has more sub-strings than the section allows."""

    count: int
    max_count: int

    @property
    def kind(self) -> str:
        return "sub_count"

    def describe(self) -> str:
        return (
            f"{self.count} sub-strings exceeds section limit of "
            f"{self.max_count}"
        )


class LineLengthValidationError(ValueError):
    """Raised in strict mode when a row exceeds the display-width limit."""

    def __init__(self, row_id: str, issues: list):
        self.row_id = row_id
        self.issues = issues
        details = "; ".join(i.describe() for i in issues)
        super().__init__(f"Line length violation at {row_id}: {details}")


def validate_line_length(
    target: str,
    max_display_width: int,
    max_sub_count: int = 0,
    margin: float = 1.0,
) -> list:
    """
    Check a single target string against section limits.

    :param target: Translated text (may contain ``{j}`` separators).
    :param max_display_width: Maximum display width from ``headers.json``.
    :param max_sub_count: Maximum sub-string count (0 = skip check).
    :param margin: Multiplier on max_display_width (default 1.0).
    :return: List of :class:`LineLengthIssue` / :class:`SubCountIssue`.
    """
    from .common import _JOIN_SPLIT_RE

    issues: list = []
    parts = _JOIN_SPLIT_RE.split(target)
    effective_max = int(max_display_width * margin)

    if max_sub_count > 0 and len(parts) > max_sub_count:
        issues.append(SubCountIssue(len(parts), max_sub_count))

    for i, part in enumerate(parts):
        w = display_width(part)
        if w > effective_max:
            issues.append(LineLengthIssue(i, w, effective_max))

    return issues


@dataclass
class LineLengthValidator:
    """
    Stateful collector that validates rows one at a time.

    Mirrors :class:`PlaceholderValidator` — collects issues for a
    summary log, or raises in strict mode.
    """

    max_display_width: int = 0
    max_sub_count: int = 0
    margin: float = 1.0
    strict: bool = False
    _rows: list[tuple[str, list]] = field(default_factory=list)

    def check(self, row_id: str, target: str) -> None:
        """Validate one row's target text against the section limits."""
        if self.max_display_width <= 0:
            return  # no limits configured
        issues = validate_line_length(
            target, self.max_display_width, self.max_sub_count,
            margin=self.margin,
        )
        if not issues:
            return
        self._rows.append((row_id, issues))
        if self.strict:
            raise LineLengthValidationError(row_id, issues)

    @property
    def issue_count(self) -> int:
        return len(self._rows)

    @property
    def rows(self) -> list[tuple[str, list]]:
        return list(self._rows)

    def log_summary(self, input_file: str, *, max_detailed: int = 5) -> None:
        """Log a WARNING-level summary of all collected violations."""
        if not self._rows:
            return
        logger.warning(
            "Line length validation: %d row(s) in '%s' exceed the "
            "display-width limit (max %d × %.2f = %d cells). "
            "Translations may overflow in-game text boxes.",
            self.issue_count, input_file,
            self.max_display_width, self.margin,
            int(self.max_display_width * self.margin),
        )
        for row_id, issues in self._rows[:max_detailed]:
            for issue in issues:
                logger.warning("  %s: %s", row_id, issue.describe())
        if len(self._rows) > max_detailed:
            logger.warning(
                "  ... and %d more row(s).",
                len(self._rows) - max_detailed,
            )


def validate_translation_file_line_lengths(
    input_file: str,
    *,
    headers_path: str = "headers.json",
    xpath: str | None = None,
    margin: float = 1.0,
    strict: bool = False,
) -> LineLengthValidator:
    """
    Walk a translation CSV/JSON and validate every row's display width.

    Resolves the section xpath from JSON metadata or the CSV filename,
    looks up ``max_display_width`` / ``max_sub_count`` in headers.json,
    then checks every row whose target differs from source.

    :param input_file: Path to a translation CSV or JSON.
    :param headers_path: Path to headers.json.
    :param xpath: Explicit xpath override (inferred if None).
    :param margin: Display-width multiplier.
    :param strict: Raise on first violation.
    :return: Populated :class:`LineLengthValidator`.
    """
    from .common import read_extraction_config, _JOIN_SPLIT_RE
    from .import_data import infer_xpath

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Translation file not found: {input_file}")

    # Resolve xpath
    if xpath is None:
        xpath = infer_xpath(input_file, headers_path)
    if xpath is None:
        raise ValueError(
            f"Cannot infer xpath for '{input_file}'. "
            "Pass --xpath explicitly or ensure the filename encodes the section path."
        )

    config = read_extraction_config(xpath, headers_path)
    max_w = config.get("max_display_width", 0)
    max_s = config.get("max_sub_count", 0)
    if max_w <= 0:
        logger.info(
            "No max_display_width in headers.json for '%s'; "
            "run --measure-line-lengths first.", xpath
        )
        return LineLengthValidator(strict=strict)

    validator = LineLengthValidator(
        max_display_width=max_w,
        max_sub_count=max_s,
        margin=margin,
        strict=strict,
    )

    if input_file.lower().endswith(".json"):
        with open(input_file, "r", encoding="utf-8") as fh:
            data = _json.load(fh)
        for i, entry in enumerate(data.get("strings", [])):
            if not isinstance(entry, dict):
                continue
            source = entry.get("source") or ""
            target = entry.get("target") or ""
            if source == target:
                continue
            validator.check(f"entry {i}", target)
        return validator

    with open(input_file, "r", newline="", encoding="utf-8") as fh:
        reader = _csv.reader(fh)
        try:
            next(reader)  # skip header
        except StopIteration:
            return validator
        for line_num, row in enumerate(reader, start=2):
            if len(row) < 3:
                continue
            source = row[1]
            target = row[2]
            if source == target:
                continue
            validator.check(f"line {line_num}", target)
    return validator


def measure_all_sections(
    headers_path: str = "headers.json",
    input_files: dict[str, str] | None = None,
) -> dict[str, dict[str, int]]:
    """
    Extract every section from the game binaries and measure limits.

    Returns a dict mapping xpath → ``{"max_display_width": N, "max_sub_count": M}``.

    :param headers_path: Path to headers.json.
    :param input_files: Map of file-type prefix → binary path.
    :return: Per-section measurement results.
    """
    from .common import (
        get_all_xpaths, read_extraction_config, load_file_data,
        extract_text_data_from_bytes,
    )
    from .export import FILE_TYPE_DEFAULTS

    if input_files is None:
        input_files = FILE_TYPE_DEFAULTS.copy()

    xpaths = get_all_xpaths(headers_path)
    results: dict[str, dict[str, int]] = {}

    for xpath in xpaths:
        file_type = xpath.split("/")[0]
        bin_path = input_files.get(file_type)
        if bin_path is None or not os.path.exists(bin_path):
            logger.warning("Skipping '%s': no binary at '%s'", xpath, bin_path)
            continue
        try:
            config = read_extraction_config(xpath, headers_path)
            file_data = load_file_data(bin_path)
            entries = extract_text_data_from_bytes(file_data, config)
            if entries:
                results[xpath] = measure_section_limits(entries)
                logger.info(
                    "  %s: max_display_width=%d, max_sub_count=%d",
                    xpath,
                    results[xpath]["max_display_width"],
                    results[xpath]["max_sub_count"],
                )
        except Exception as exc:
            logger.warning("Failed to measure '%s': %s", xpath, exc)

    return results


def update_headers_with_limits(
    limits: dict[str, dict[str, int]],
    headers_path: str = "headers.json",
) -> int:
    """
    Write measured limits back into headers.json.

    Navigates to each xpath's leaf node and sets ``max_display_width``
    and ``max_sub_count``. Preserves all other fields.

    :param limits: Output of :func:`measure_all_sections`.
    :param headers_path: Path to headers.json.
    :return: Number of sections updated.
    """
    with open(headers_path, "r", encoding="utf-8") as f:
        data = _json.load(f)

    updated = 0
    for xpath, vals in limits.items():
        parts = xpath.split("/")
        node = data
        try:
            for part in parts:
                node = node[part]
        except KeyError:
            logger.warning("xpath '%s' not found in headers.json, skipping", xpath)
            continue
        node["max_display_width"] = vals["max_display_width"]
        node["max_sub_count"] = vals["max_sub_count"]
        updated += 1

    with open(headers_path, "w", encoding="utf-8") as f:
        _json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    logger.info("Updated %d section(s) in %s", updated, headers_path)
    return updated
