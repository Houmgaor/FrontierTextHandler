"""
Validate that a translation preserves inline placeholders from source.

Translators edit CSV/JSON cells in tools that don't know about
FrontierTextHandler's inline marker conventions, so it's easy to
accidentally delete or mangle a ``{cNN}`` / ``{j}`` / ``{K012}``
marker. The game bytes that would have been substituted at runtime
either render incorrectly or silently corrupt the string, depending
on which family the marker came from.

This module is the tier-2 validator from the 1.6.0 format review:
it matches every marker of the form ``{letter...}`` or
``{/letter...}`` in both ``source`` and ``target``, compares the
multisets, and reports anything that appears in one and not the
other. No per-family semantic rules (that would be tier 3) — just
"did you keep all the markers you started with".

Three consumers:

1. The CSV/JSON importers (``get_new_strings`` /
   ``get_new_strings_from_json`` / ``get_new_strings_indexed``)
   run validation on every row they parse, logging a summary after
   the read finishes. With ``strict=True`` (CLI
   ``--strict-placeholders``) a mismatch raises instead.
2. The standalone ``--validate-placeholders`` CLI command runs the
   same validator on a translation file without touching the
   binary, so CI pipelines can lint every commit.
3. External Python callers can import :func:`validate_placeholders`
   and :class:`PlaceholderValidator` directly.
"""
import csv as _csv
import json as _json
import logging
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import NamedTuple

logger = logging.getLogger(__name__)


# Any brace-wrapped marker whose body starts with a letter (optionally
# preceded by a forward slash for closing tags like ``{/c}``). Matches
# every 1.6.0 placeholder family — ``{cNN}``, ``{/c}``, ``{j}``,
# ``{K012}``, ``{i131}``, ``{u4}`` — without the validator having to
# learn each family. Random brace-enclosed tokens in natural text
# (e.g. ``{item}``) also match; that's intentional, because any
# brace-shaped token the translator was supposed to preserve gets
# the same protection.
_PLACEHOLDER_RE = re.compile(r"\{/?[A-Za-z]\w*\}")


class PlaceholderIssue(NamedTuple):
    """
    A single placeholder-count mismatch between source and target.

    ``marker`` is the literal placeholder string including braces.
    ``source_count`` is how many times it appears in the source cell
    and ``target_count`` the same for the target.
    """

    marker: str
    source_count: int
    target_count: int

    @property
    def missing(self) -> bool:
        """True when the translator dropped at least one occurrence."""
        return self.target_count < self.source_count

    @property
    def extra(self) -> bool:
        """True when the target has more occurrences than source."""
        return self.target_count > self.source_count

    def describe(self) -> str:
        """One-line human-readable description for log output."""
        verb = "missing" if self.missing else "extra"
        return (
            f"{verb} {self.marker!r} "
            f"(source has {self.source_count}, target has {self.target_count})"
        )


class PlaceholderValidationError(ValueError):
    """Raised in strict mode when a row fails validation."""

    def __init__(self, row_id: str, issues: list[PlaceholderIssue]):
        self.row_id = row_id
        self.issues = issues
        details = "; ".join(i.describe() for i in issues)
        super().__init__(f"Placeholder mismatch at {row_id}: {details}")


def validate_placeholders(
    source: str, target: str
) -> list[PlaceholderIssue]:
    """
    Return every placeholder count mismatch between *source* and *target*.

    ``target`` must preserve every brace-form placeholder from
    ``source`` the same number of times. Anything that appears in one
    cell and not the other, or with a different count, produces one
    :class:`PlaceholderIssue` per distinct marker.

    :param source: The original cell in on-disk form — i.e. after
        the extractor has rewritten colour codes to ``{cNN}`` and
        grouped entries to ``{j}``, BEFORE ``color_codes_from_csv``
        runs on the way into the binary.
    :param target: The translated cell in the same form.
    :return: A list of :class:`PlaceholderIssue`, one per mismatched
        marker. Empty list when the multisets are equal.
    """
    src_markers = _PLACEHOLDER_RE.findall(source)
    tgt_markers = _PLACEHOLDER_RE.findall(target)
    if src_markers == tgt_markers:
        # Fast path: identical marker sequences — no mismatch possible.
        return []

    src_counts = Counter(src_markers)
    tgt_counts = Counter(tgt_markers)
    issues: list[PlaceholderIssue] = []
    for marker in sorted(set(src_counts) | set(tgt_counts)):
        sc = src_counts.get(marker, 0)
        tc = tgt_counts.get(marker, 0)
        if sc != tc:
            issues.append(PlaceholderIssue(marker, sc, tc))
    return issues


@dataclass
class PlaceholderValidator:
    """
    Stateful collector that validates rows one at a time.

    Each call to :meth:`check` runs :func:`validate_placeholders` and
    either raises (strict mode) or records the issue for later
    summary logging via :meth:`log_summary`.
    """

    strict: bool = False
    _rows: list[tuple[str, list[PlaceholderIssue]]] = field(default_factory=list)

    def check(self, row_id: str, source: str, target: str) -> None:
        """
        Validate a single row's source/target pair.

        :param row_id: Human-readable row identifier for error messages
            (e.g. ``"line 42"`` or ``"entry 7"``).
        :param source: Source cell in on-disk form.
        :param target: Target cell in on-disk form.
        :raises PlaceholderValidationError: In strict mode, when the
            row has at least one issue.
        """
        issues = validate_placeholders(source, target)
        if not issues:
            return
        self._rows.append((row_id, issues))
        if self.strict:
            raise PlaceholderValidationError(row_id, issues)

    @property
    def issue_count(self) -> int:
        """Number of rows with at least one placeholder issue."""
        return len(self._rows)

    @property
    def rows(self) -> list[tuple[str, list[PlaceholderIssue]]]:
        """All collected issues, for callers that want to render them."""
        return list(self._rows)

    def log_summary(self, input_file: str, *, max_detailed: int = 5) -> None:
        """
        Log a WARNING-level summary of all collected issues.

        Prints a header with the count, then the first *max_detailed*
        rows with their individual issue lines. A ``... and N more``
        footer is added when the collection exceeds the limit.

        No-op when no issues were collected.
        """
        if not self._rows:
            return
        logger.warning(
            "Placeholder validation: %d row(s) in '%s' have "
            "placeholder mismatches between source and target. "
            "Translations dropped a marker or added an unexpected one; "
            "the binary may render incorrectly.",
            self.issue_count, input_file,
        )
        for row_id, issues in self._rows[:max_detailed]:
            for issue in issues:
                logger.warning("  %s: %s", row_id, issue.describe())
        if len(self._rows) > max_detailed:
            logger.warning(
                "  ... and %d more row(s). Run "
                "'python main.py --validate-placeholders %s' for the "
                "full report.",
                len(self._rows) - max_detailed, input_file,
            )


def validate_translation_file(
    input_file: str, *, strict: bool = False,
) -> PlaceholderValidator:
    """
    Walk a translation CSV/JSON and validate every row's placeholders.

    Unlike the inline validators that run during an import, this
    function is side-effect-free: it reads the file, collects every
    issue in a :class:`PlaceholderValidator`, and returns the
    collector so callers can render a report, decide to proceed, or
    exit non-zero in a CI pipeline.

    Both CSV shapes (index-keyed and legacy offset-keyed) and JSON
    are supported. Rows whose ``target`` equals ``source`` — the
    default after a fresh extract — are still checked, though they
    can't have a mismatch by construction so the check is free.

    :param input_file: Path to an index-keyed or legacy offset-keyed
        CSV or JSON translation file.
    :param strict: If True, raise at the first issue instead of
        collecting all of them.
    :return: The populated validator.
    :raises FileNotFoundError: If *input_file* does not exist.
    :raises ValueError: If the file shape is unrecognised.
    :raises PlaceholderValidationError: In strict mode, at the first
        bad row.
    """
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Translation file not found: {input_file}")

    validator = PlaceholderValidator(strict=strict)

    if input_file.lower().endswith(".json"):
        with open(input_file, "r", encoding="utf-8") as fh:
            data = _json.load(fh)
        if not isinstance(data, dict) or "strings" not in data:
            raise ValueError(
                f"JSON translation file '{input_file}' has no 'strings' key"
            )
        for i, entry in enumerate(data["strings"]):
            if not isinstance(entry, dict):
                continue
            source = entry.get("source") or ""
            target = entry.get("target") or ""
            validator.check(f"entry {i}", source, target)
        return validator

    with open(input_file, "r", newline="", encoding="utf-8") as fh:
        reader = _csv.reader(fh)
        try:
            next(reader)  # skip header row
        except StopIteration:
            return validator
        for line_num, row in enumerate(reader, start=2):
            if len(row) < 3:
                continue
            source = row[1]
            target = row[2]
            validator.check(f"line {line_num}", source, target)
    return validator
