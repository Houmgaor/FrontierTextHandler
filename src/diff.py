"""
Compare strings between two files (binary, CSV, or JSON) and report differences.
"""
import csv
import json
import logging
import os
from dataclasses import dataclass, field

from .common import (
    extract_text_data,
    extract_ftxt,
    extract_quest_file,
    extract_npc_dialogue,
    read_extraction_config,
    load_file_data,
    skip_csv_header,
)

logger = logging.getLogger(__name__)


@dataclass
class DiffResult:
    """Result of comparing strings between two files."""
    file_a: str
    file_b: str
    modified: list[tuple[str, str, str]] = field(default_factory=list)  # (location, old, new)
    added: list[tuple[str, str]] = field(default_factory=list)          # (location, text)
    removed: list[tuple[str, str]] = field(default_factory=list)        # (location, text)
    unchanged: int = 0


def _location_key(location: str) -> str:
    """
    Extract the hex offset from a location string, stripping the @filename part.

    :param location: Location string like "0x1234@mhfdat.bin" or just "0x1234"
    :return: Hex offset string like "0x1234"
    """
    if "@" in location:
        return location[:location.index("@")]
    return location


def load_strings_from_csv(csv_path: str) -> dict[str, str]:
    """
    Load strings from a CSV file.

    Reads the 'target' column (column 3) keyed by hex offset from 'location' (column 1).

    :param csv_path: Path to the CSV file
    :return: Dict mapping hex offset to target text
    """
    strings: dict[str, str] = {}
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        skip_csv_header(reader, csv_path)
        for line in reader:
            if not line or len(line) < 3:
                continue
            key = _location_key(line[0])
            strings[key] = line[2]
    return strings


def load_strings_from_json(json_path: str) -> dict[str, str]:
    """
    Load strings from a JSON file.

    Reads the 'target' column from each entry in the 'strings' array,
    keyed by hex offset from 'location'.

    :param json_path: Path to the JSON file
    :return: Dict mapping hex offset to target text
    """
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    strings: dict[str, str] = {}
    for entry in data.get("strings", []):
        if not isinstance(entry, dict):
            continue
        if "location" not in entry or "target" not in entry:
            continue
        key = _location_key(entry["location"])
        strings[key] = entry["target"]
    return strings


def load_strings_from_binary(
    bin_path: str,
    mode: str,
    xpath: str = None,
) -> dict[str, str]:
    """
    Extract strings from a binary file using the appropriate extractor.

    :param bin_path: Path to the binary file
    :param mode: Extraction mode: "xpath", "ftxt", "quest", or "npc"
    :param xpath: XPath for mode="xpath" (e.g., "dat/armors/head")
    :return: Dict mapping hex offset to text
    """
    if mode == "xpath":
        if not xpath:
            raise ValueError("--xpath is required when diffing binary files")
        config = read_extraction_config(xpath)
        entries = extract_text_data(bin_path, config)
    elif mode == "ftxt":
        entries = extract_ftxt(bin_path)
    elif mode == "quest":
        entries = extract_quest_file(bin_path)
    elif mode == "npc":
        entries = extract_npc_dialogue(bin_path)
    else:
        raise ValueError(f"Unknown extraction mode: {mode}")

    return {f"0x{e['offset']:x}": e["text"] for e in entries}


def load_strings(
    file_path: str,
    mode: str = None,
    xpath: str = None,
) -> dict[str, str]:
    """
    Load strings from a file, auto-detecting CSV vs binary.

    CSV files are detected by .csv extension. Everything else is treated as binary.

    :param file_path: Path to the file
    :param mode: Extraction mode for binary files: "xpath", "ftxt", "quest", "npc"
    :param xpath: XPath for mode="xpath"
    :return: Dict mapping hex offset to text
    """
    if file_path.lower().endswith(".csv"):
        return load_strings_from_csv(file_path)
    elif file_path.lower().endswith(".json"):
        return load_strings_from_json(file_path)
    else:
        if not mode:
            raise ValueError(
                "Binary files require a mode flag (--xpath, --ftxt, --quest, or --npc)"
            )
        return load_strings_from_binary(file_path, mode, xpath)


def diff_strings(
    strings_a: dict[str, str],
    strings_b: dict[str, str],
    file_a: str,
    file_b: str,
) -> DiffResult:
    """
    Compare two string dictionaries and return structured diff.

    :param strings_a: Strings from file A (keyed by hex offset)
    :param strings_b: Strings from file B (keyed by hex offset)
    :param file_a: Display name for file A
    :param file_b: Display name for file B
    :return: DiffResult with modified, added, removed, and unchanged counts
    """
    result = DiffResult(file_a=file_a, file_b=file_b)

    keys_a = set(strings_a.keys())
    keys_b = set(strings_b.keys())

    # Keys in both
    for key in sorted(keys_a & keys_b):
        if strings_a[key] == strings_b[key]:
            result.unchanged += 1
        else:
            result.modified.append((key, strings_a[key], strings_b[key]))

    # Keys only in B (added)
    for key in sorted(keys_b - keys_a):
        result.added.append((key, strings_b[key]))

    # Keys only in A (removed)
    for key in sorted(keys_a - keys_b):
        result.removed.append((key, strings_a[key]))

    return result


def format_diff(result: DiffResult) -> str:
    """
    Format a DiffResult as human-readable text output.

    :param result: DiffResult to format
    :return: Formatted string
    """
    total = (
        len(result.modified) + len(result.added) + len(result.removed) + result.unchanged
    )
    lines = [f"Diff: {result.file_a} vs {result.file_b} ({total:,} strings)"]

    if result.modified:
        lines.append(f"\nModified ({len(result.modified)}):")
        for loc, old, new in result.modified:
            lines.append(f'  {loc}  "{old}" -> "{new}"')

    if result.added:
        lines.append(f"\nAdded ({len(result.added)}):")
        for loc, text in result.added:
            lines.append(f'  {loc}  "{text}"')

    if result.removed:
        lines.append(f"\nRemoved ({len(result.removed)}):")
        for loc, text in result.removed:
            lines.append(f'  {loc}  "{text}"')

    if not result.modified and not result.added and not result.removed:
        lines.append("\nNo differences found.")

    lines.append(
        f"\nSummary: {len(result.modified)} modified, {len(result.added)} added, "
        f"{len(result.removed)} removed, {result.unchanged} unchanged"
    )

    return "\n".join(lines)
