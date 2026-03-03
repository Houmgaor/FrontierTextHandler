"""
Shared CSV/JSON row loading utilities.

Provides low-level row iteration for CSV and JSON translation files,
used by both :mod:`src.diff` and :mod:`src.merge`.
"""
import csv
import json
from typing import Iterator

from .common import skip_csv_header


def _location_key(location: str) -> str:
    """
    Extract the hex offset from a location string, stripping the @filename part.

    :param location: Location string like "0x1234@mhfdat.bin" or just "0x1234"
    :return: Hex offset string like "0x1234"
    """
    if "@" in location:
        return location[:location.index("@")]
    return location


def iter_csv_rows(path: str) -> Iterator[dict]:
    """
    Iterate over rows in a CSV file, yielding dicts with location/source/target keys.

    Skips malformed rows (fewer than 3 columns).

    :param path: Path to the CSV file
    :yields: Dicts with "location", "source", "target" keys
    """
    with open(path, "r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        skip_csv_header(reader, path)
        for line in reader:
            if not line or len(line) < 3:
                continue
            yield {"location": line[0], "source": line[1], "target": line[2]}


def iter_json_rows(path: str) -> Iterator[dict]:
    """
    Iterate over entries in a JSON file's "strings" array.

    Skips entries missing required keys.

    :param path: Path to the JSON file
    :yields: Dicts with "location", "source", "target" keys
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for entry in data.get("strings", []):
        if not isinstance(entry, dict):
            continue
        if "location" not in entry or "target" not in entry:
            continue
        yield {
            "location": entry["location"],
            "source": entry.get("source", ""),
            "target": entry["target"],
        }


def iter_rows(path: str) -> Iterator[dict]:
    """
    Auto-detect format by extension and iterate over rows.

    :param path: Path to the CSV or JSON file
    :yields: Dicts with "location", "source", "target" keys
    """
    if path.lower().endswith(".json"):
        yield from iter_json_rows(path)
    else:
        yield from iter_csv_rows(path)
