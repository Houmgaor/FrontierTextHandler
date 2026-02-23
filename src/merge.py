"""
Merge translations from an old translated CSV/JSON into a freshly extracted CSV/JSON.

When game binaries are updated, translators must re-extract fresh files. This module
carries over existing translations where the source string is unchanged, and flags
entries where the source has been modified for review.
"""
import csv
import json
import logging
import os
from dataclasses import dataclass, field

from .common import skip_csv_header
from .diff import _location_key

logger = logging.getLogger(__name__)


@dataclass
class MergeResult:
    """Result of merging translations between old and new files."""
    old_file: str
    new_file: str
    carried: int = 0
    unchanged: int = 0
    modified_source: list[tuple[str, str, str, str]] = field(default_factory=list)
    new_strings: int = 0
    removed: int = 0


def load_translations_from_csv(path: str) -> dict[str, tuple[str, str]]:
    """
    Load a CSV file returning offset -> (source, target) for all rows.

    :param path: Path to the CSV file
    :return: Dict mapping hex offset to (source, target) tuple
    """
    translations: dict[str, tuple[str, str]] = {}
    with open(path, "r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        skip_csv_header(reader, path)
        for line in reader:
            if not line or len(line) < 3:
                continue
            key = _location_key(line[0])
            translations[key] = (line[1], line[2])
    return translations


def load_translations_from_json(path: str) -> dict[str, tuple[str, str]]:
    """
    Load a JSON file returning offset -> (source, target) for all rows.

    :param path: Path to the JSON file
    :return: Dict mapping hex offset to (source, target) tuple
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    translations: dict[str, tuple[str, str]] = {}
    for entry in data.get("strings", []):
        if not isinstance(entry, dict):
            continue
        if "location" not in entry or "source" not in entry or "target" not in entry:
            continue
        key = _location_key(entry["location"])
        translations[key] = (entry["source"], entry["target"])
    return translations


def load_translations(path: str) -> dict[str, tuple[str, str]]:
    """
    Auto-detect CSV/JSON by extension and load translations.

    :param path: Path to the file
    :return: Dict mapping hex offset to (source, target) tuple
    """
    if path.lower().endswith(".json"):
        return load_translations_from_json(path)
    return load_translations_from_csv(path)


def merge_translations(
    old_path: str,
    new_path: str,
) -> tuple[MergeResult, list[dict]]:
    """
    Merge old translations into a new extracted structure.

    For each string in the new file:
    - Carried: same offset, same source, old had a translation -> carry over
    - Unchanged: same offset, same source, no translation existed -> keep as-is
    - Modified source: same offset, source text changed -> flag for review
    - New: offset not in old file -> leave untranslated

    :param old_path: Path to old translated CSV/JSON
    :param new_path: Path to freshly extracted CSV/JSON
    :return: (MergeResult, rows) where rows are dicts with location/source/target keys
    """
    old_data = load_translations(old_path)
    new_data = load_translations(new_path)

    result = MergeResult(
        old_file=os.path.basename(old_path),
        new_file=os.path.basename(new_path),
    )

    # Reload new file to preserve row order and full location strings
    new_rows = _load_ordered_rows(new_path)

    merged_rows = []
    new_keys = set()

    for row in new_rows:
        key = _location_key(row["location"])
        new_keys.add(key)
        new_source = row["source"]

        if key in old_data:
            old_source, old_target = old_data[key]
            if old_source == new_source:
                if old_target != old_source:
                    # Carry over translation
                    merged_rows.append({
                        "location": row["location"],
                        "source": new_source,
                        "target": old_target,
                    })
                    result.carried += 1
                else:
                    # No translation existed
                    merged_rows.append({
                        "location": row["location"],
                        "source": new_source,
                        "target": new_source,
                    })
                    result.unchanged += 1
            else:
                # Source changed - do not carry translation
                merged_rows.append({
                    "location": row["location"],
                    "source": new_source,
                    "target": new_source,
                })
                result.modified_source.append((key, old_source, new_source, old_target))
        else:
            # New string
            merged_rows.append({
                "location": row["location"],
                "source": new_source,
                "target": new_source,
            })
            result.new_strings += 1

    # Count removed strings (in old but not in new)
    old_keys = set(old_data.keys())
    result.removed = len(old_keys - new_keys)

    return result, merged_rows


def _load_ordered_rows(path: str) -> list[dict]:
    """
    Load rows from a CSV or JSON file preserving order.

    :param path: Path to the file
    :return: List of dicts with location/source/target keys
    """
    if path.lower().endswith(".json"):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        rows = []
        for entry in data.get("strings", []):
            if not isinstance(entry, dict):
                continue
            if "location" not in entry or "source" not in entry or "target" not in entry:
                continue
            rows.append({
                "location": entry["location"],
                "source": entry["source"],
                "target": entry["target"],
            })
        return rows
    else:
        rows = []
        with open(path, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            skip_csv_header(reader, path)
            for line in reader:
                if not line or len(line) < 3:
                    continue
                rows.append({
                    "location": line[0],
                    "source": line[1],
                    "target": line[2],
                })
        return rows


def write_merged_csv(rows: list[dict], output_path: str) -> int:
    """
    Write merged rows as a standard CSV file.

    :param rows: List of dicts with location/source/target keys
    :param output_path: Output file path
    :return: Number of rows written
    """
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["location", "source", "target"])
        for row in rows:
            writer.writerow([row["location"], row["source"], row["target"]])
    return len(rows)


def write_merged_json(rows: list[dict], output_path: str, source_file: str = "") -> int:
    """
    Write merged rows as a JSON file with metadata.

    :param rows: List of dicts with location/source/target keys
    :param output_path: Output file path
    :param source_file: Source file name for metadata
    :return: Number of entries written
    """
    from . import __version__

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    output = {
        "metadata": {
            "source_file": source_file,
            "version": __version__,
        },
        "strings": rows,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    return len(rows)


def write_merged(rows: list[dict], output_path: str, source_file: str = "") -> int:
    """
    Auto-detect format by extension and write merged output.

    :param rows: List of dicts with location/source/target keys
    :param output_path: Output file path
    :param source_file: Source file name for JSON metadata
    :return: Number of entries written
    """
    if output_path.lower().endswith(".json"):
        return write_merged_json(rows, output_path, source_file)
    return write_merged_csv(rows, output_path)


def format_merge_report(result: MergeResult) -> str:
    """
    Format a human-readable merge summary.

    :param result: MergeResult to format
    :return: Formatted string
    """
    total = result.carried + result.unchanged + len(result.modified_source) + result.new_strings
    lines = [f"Merge: {result.old_file} + {result.new_file} ({total:,} strings)"]

    lines.append(f"\n  Carried:   {result.carried:>6} translations preserved")
    lines.append(f"  Unchanged: {result.unchanged:>6} (no translation existed)")
    lines.append(f"  Modified:  {len(result.modified_source):>6} (source changed, needs review)")
    lines.append(f"  New:       {result.new_strings:>6} (not in old file)")
    lines.append(f"  Removed:   {result.removed:>6} (not in new file)")

    if result.modified_source:
        lines.append(f"\nModified source strings ({len(result.modified_source)}):")
        for offset, old_source, new_source, old_target in result.modified_source:
            lines.append(f"  {offset}:")
            lines.append(f'    old source: "{old_source}"')
            lines.append(f'    new source: "{new_source}"')
            lines.append(f'    old target: "{old_target}" (NOT carried)')

    return "\n".join(lines)
