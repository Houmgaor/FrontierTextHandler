"""
Import data from a CSV file to a binary file.
"""
import csv
import json
import logging
import os
import re
import shutil
import struct
from typing import Optional

from .binary_file import BinaryFile
from . import common
from .common import (
    encode_game_string,
    EncodingError,
    color_codes_from_csv,
    JOIN_MARKER,
    _JOIN_SPLIT_RE,
)
from .jkr_decompress import is_jkr_file, decompress_jkr
from .jkr_compress import compress_jkr_hfi
from .crypto import is_encrypted_file, decrypt, encode_ecd, DEFAULT_KEY_INDEX

logger = logging.getLogger(__name__)


class CSVParseError(ValueError):
    """Raised when CSV parsing fails due to malformed data."""
    pass


def _entry_sub_offsets(entry: dict) -> list[int]:
    """
    Return the per-sub pointer-slot offsets of a live extractor entry.

    1.6.0+ extractors populate ``entry["sub_offsets"]`` — a list with
    one slot per ``{j}``-separated sub-string (length 1 for non-grouped
    entries). Older callers that build entry dicts by hand may omit the
    field entirely; in that case we fall back to reading per-sub
    offsets from any legacy ``<join at="N">`` tags in the text, with a
    final fallback to ``[entry["offset"]]``.
    """
    subs = entry.get("sub_offsets")
    if subs:
        return [int(s) for s in subs]
    text = str(entry.get("text", ""))
    if "<join at=" in text:
        pairs = parse_joined_text(int(entry["offset"]), text)
        return [int(off) for off, _ in pairs]
    return [int(entry["offset"])]


def parse_location(location: str) -> int:
    """
    Parse a location string from CSV format to a pointer offset.

    :param location: Location string in format "0x1234@filename.bin"
    :return: The pointer offset as an integer
    :raises CSVParseError: If the location string is malformed
    """
    if "@" not in location:
        raise CSVParseError(
            f"Invalid location format '{location}': missing '@' separator. "
            "Expected format: '0x1234@filename.bin'"
        )
    try:
        hex_part = location[:location.index("@")]
        return int(hex_part, 16)
    except ValueError as exc:
        raise CSVParseError(
            f"Invalid hex offset in location '{location}': {hex_part}"
        ) from exc


def get_new_strings(input_file: str) -> list[tuple[int, str]]:
    """
    Get the new strings defined in a CSV file.

    :param input_file: Input CSV file path.
    :return: New strings defined in the file as list of (offset, string) tuples
    :raises CSVParseError: If CSV format is invalid
    """
    new_strings: list[tuple[int, str]] = []
    with open(input_file, "r", newline="", encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile)
        common.skip_csv_header(reader, input_file)
        for line_num, line in enumerate(reader, start=2):  # +2 for header + 0-index
            # Skip empty lines
            if not line:
                continue
            # Validate line has required columns
            if len(line) < 3:
                logger.warning(
                    "Line %d in '%s' has fewer than 3 columns, skipping",
                    line_num, input_file
                )
                continue
            # Skip if translation is same as source
            if line[1] == line[2]:
                continue
            try:
                index = parse_location(line[0])
                new_strings.append((index, color_codes_from_csv(line[2])))
            except CSVParseError as exc:
                logger.warning("Line %d: %s", line_num, exc)
                continue
    return new_strings


def get_new_strings_from_json(input_file: str) -> list[tuple[int, str]]:
    """
    Get the new strings defined in a JSON file.

    :param input_file: Input JSON file path.
    :return: New strings defined in the file as list of (offset, string) tuples
    :raises CSVParseError: If JSON format is invalid
    """
    with open(input_file, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            raise CSVParseError(f"Invalid JSON in '{input_file}': {exc}") from exc

    if "strings" not in data:
        raise CSVParseError(f"Missing 'strings' key in JSON file '{input_file}'")

    new_strings: list[tuple[int, str]] = []
    for i, entry in enumerate(data["strings"]):
        if not isinstance(entry, dict):
            logger.warning("Entry %d in '%s' is not an object, skipping", i, input_file)
            continue
        for key in ("location", "source", "target"):
            if key not in entry:
                logger.warning(
                    "Entry %d in '%s' missing '%s' key, skipping", i, input_file, key
                )
                break
        else:
            # Skip if translation is same as source
            if entry["source"] == entry["target"]:
                continue
            try:
                index = parse_location(entry["location"])
                new_strings.append((index, color_codes_from_csv(entry["target"])))
            except CSVParseError as exc:
                logger.warning("Entry %d: %s", i, exc)
                continue
    return new_strings


def detect_translation_format(input_file: str) -> str:
    """
    Detect whether a CSV/JSON translation file uses index-based or
    offset-based location keys.

    :param input_file: CSV or JSON path
    :return: ``"index"`` if the file has an ``index`` column/field,
        otherwise ``"offset"`` (the legacy format)
    """
    if input_file.lower().endswith(".json"):
        with open(input_file, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return "offset"
        strings = data.get("strings") if isinstance(data, dict) else None
        if isinstance(strings, list) and strings and isinstance(strings[0], dict):
            return "index" if "index" in strings[0] else "offset"
        return "offset"

    with open(input_file, "r", newline="", encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile)
        try:
            header = next(reader)
        except StopIteration:
            return "offset"
        return "index" if header and header[0].strip().lower() == "index" else "offset"


def get_new_strings_indexed(input_file: str) -> list[tuple[int, str]]:
    """
    Read translations keyed by stable pointer-table index.

    Returns ``(index, target)`` pairs for rows whose ``target`` differs
    from ``source``.  The caller must resolve indexes to file offsets
    against the freshly-extracted section.

    :param input_file: CSV or JSON file with an ``index`` column/field
    :return: List of ``(index, text)`` tuples
    :raises CSVParseError: If a row has a malformed index
    """
    pairs: list[tuple[int, str]] = []

    if input_file.lower().endswith(".json"):
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        for i, entry in enumerate(data.get("strings", [])):
            if not isinstance(entry, dict) or "index" not in entry:
                continue
            if entry.get("source") == entry.get("target"):
                continue
            try:
                pairs.append((
                    int(entry["index"]),
                    color_codes_from_csv(entry["target"]),
                ))
            except (TypeError, ValueError) as exc:
                logger.warning("Entry %d: invalid index %r: %s", i, entry.get("index"), exc)
        return pairs

    with open(input_file, "r", newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for line_num, row in enumerate(reader, start=2):
            if not row.get("index", "").strip():
                continue
            if row.get("source") == row.get("target"):
                continue
            try:
                pairs.append((
                    int(row["index"]),
                    color_codes_from_csv(row["target"]),
                ))
            except ValueError as exc:
                logger.warning("Line %d: invalid index %r: %s", line_num, row.get("index"), exc)
    return pairs


def read_json_metadata(input_file: str) -> dict:
    """
    Read the ``metadata`` block from an index-keyed JSON translation file.

    :param input_file: Path to a JSON file
    :return: The metadata dict, or ``{}`` if the file is not JSON,
        is unreadable, or has no metadata block.
    """
    if not input_file.lower().endswith(".json"):
        return {}
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    meta = data.get("metadata") if isinstance(data, dict) else None
    return meta if isinstance(meta, dict) else {}


def infer_xpath(
    input_file: str,
    headers_path: str = common.DEFAULT_HEADERS_PATH,
) -> Optional[str]:
    """
    Infer the section xpath for an index-keyed translation file.

    Sources, in order of preference:

    1. ``metadata.xpath`` in a JSON file (set by ``export_as_json`` when
       writing index-keyed output).
    2. The CSV/JSON filename: ``dat-armors-head.csv`` → ``dat/armors/head``
       if that xpath exists in *headers_path*.

    :param input_file: Path to the index-keyed CSV or JSON file
    :param headers_path: Path to headers.json (for filename validation)
    :return: An xpath string, or ``None`` if no source could be inferred
    """
    # 1. JSON metadata
    xpath = read_json_metadata(input_file).get("xpath")
    if isinstance(xpath, str) and xpath:
        return xpath

    # 2. Filename-derived: <prefix>-<a>-<b>-...-<z>.{csv,json} → prefix/a/b/.../z
    basename = os.path.splitext(os.path.basename(input_file))[0]
    if "-" in basename:
        candidate = basename.replace("-", "/")
        try:
            available = set(common.get_all_xpaths(headers_path))
        except (FileNotFoundError, KeyError):
            return None
        if candidate in available:
            return candidate
    return None


def _expand_legacy_join_tags(
    entries: list[tuple[int, str]],
) -> list[tuple[int, str]]:
    """
    Expand pre-1.6.0 ``<join at="N">`` tags into per-sub pairs.

    Each input tuple whose text contains ``<join at="N">`` markers is
    replaced by one tuple per sub-string, using the offsets embedded
    in the tags. Entries without the marker pass through unchanged.
    Does **not** handle the new ``{j}`` marker — that requires a live
    config, see :func:`resolve_offsets_with_groups`.

    :param entries: List of ``(offset, text)`` tuples
    :return: Flattened list with grouped entries expanded
    """
    expanded: list[tuple[int, str]] = []
    for offset, text in entries:
        if "<join at=" in text:
            expanded.extend(parse_joined_text(offset, text))
        else:
            expanded.append((offset, text))
    return expanded


def resolve_offsets_with_groups(
    entries: list[tuple[int, str]],
    file_data: bytes,
    config: dict,
) -> list[tuple[int, str]]:
    """
    Expand ``{j}``-marker grouped translations against a live section.

    Like :func:`resolve_indexes_to_offsets` but keyed by absolute
    first-pointer offset instead of slot index. Used on the legacy
    location-keyed release JSON path so grouped translations with
    1.6.0+ ``{j}`` markers still apply per-sub.

    :param entries: ``(first_offset, text)`` tuples from the release JSON
    :param file_data: Decrypted/decompressed binary data
    :param config: Extraction config for the section
    :return: Flat list of ``(ptr_offset, sub_text)`` tuples
    :raises ValueError: If a grouped entry's first offset does not
        match any live entry, or the sub-string count differs
    """
    from .common import extract_text_data_from_bytes
    live_entries = extract_text_data_from_bytes(file_data, config)
    live_by_first = {
        int(e["offset"]): _entry_sub_offsets(e) for e in live_entries
    }

    expanded: list[tuple[int, str]] = []
    for offset, text in entries:
        if not _has_join_marker(text):
            expanded.append((offset, text))
            continue
        live_offsets = live_by_first.get(offset)
        if live_offsets is None:
            raise ValueError(
                f"Grouped translation at offset 0x{offset:x} does "
                f"not match any live entry in this section"
            )
        subs = split_group_text(text)
        if len(subs) != len(live_offsets):
            raise ValueError(
                f"Grouped entry at 0x{offset:x}: translation has "
                f"{len(subs)} sub-strings but the live section has "
                f"{len(live_offsets)}. Re-extract and merge."
            )
        for live_off, sub in zip(live_offsets, subs):
            expanded.append((live_off, sub))
    return expanded


def resolve_indexes_against_entries(
    indexed: list[tuple[int, str]],
    live_entries: list[dict],
    *,
    context: str = "section",
    expand_groups: bool = True,
) -> list[tuple[int, str]]:
    """
    Resolve ``(index, text)`` pairs to ``(offset, text)`` via positional
    alignment against a pre-extracted list of live entries.

    This is the format-agnostic core used by both the config-driven
    path (:func:`resolve_indexes_to_offsets`) and the standalone-file
    paths (FTXT, NPC dialogue, scenario, quest). Every extractor in
    the project returns entries in the same ``{"offset": int,
    "text": str}`` shape, so the alignment logic is identical.

    Two output modes are supported:

    - ``expand_groups=True`` (default): grouped entries are fanned out
      into one ``(live_ptr_offset, sub_text)`` pair per sub-string.
      The caller sees fully-expanded pointers and doesn't have to
      re-parse join markers. Used by ``rebuild_section`` and
      ``append_to_binary`` callers (where each pair is a standalone
      pointer update).
    - ``expand_groups=False``: grouped entries stay as a single
      ``(entry_offset, joined_text)`` pair with ``{j}`` markers
      between sub-strings. Used by ``rebuild_ftxt``,
      ``rebuild_npc_dialogue``, and ``rebuild_scenario_file``, which
      key their internal translation map by entry-level offset and
      split the joined text themselves.

    In both modes, a grouped entry whose sub-string count does not
    match the live entry raises a ``ValueError`` — this is the
    primary integrity check for index-keyed imports.

    :param indexed: List of ``(index, text)`` tuples
    :param live_entries: Pre-extracted entries, typically the output
        of the same extractor that produced the CSV/JSON in the first
        place (``extract_text_data_from_bytes``, ``extract_ftxt_data``,
        ``extract_npc_dialogue_data``, ``extract_scenario_file_data``,
        or ``extract_quest_file_data``).
    :param context: Short label for error messages (e.g. ``"FTXT"``,
        ``"NPC dialogue"``, ``"scenario"``, ``"quest file"``).
    :param expand_groups: If True (default), expand grouped entries
        into per-sub ``(ptr_offset, sub_text)`` pairs. If False,
        return one ``(entry_offset, joined_text)`` pair per grouped
        entry with the canonical ``{j}`` marker between sub-strings.
    :return: List of ``(offset, text)`` tuples
    :raises ValueError: If any index is out of range, or if a grouped
        entry's sub-string count does not match the live entry.
    """
    resolved: list[tuple[int, str]] = []
    for index, text in indexed:
        if index < 0 or index >= len(live_entries):
            raise ValueError(
                f"Translation index {index} is out of range for {context} "
                f"with {len(live_entries)} entries. The source file may "
                f"have changed; re-extract and merge translations to "
                f"update the file."
            )
        live_entry = live_entries[index]
        live_text = str(live_entry["text"])
        live_offset = int(live_entry["offset"])
        live_offsets = _entry_sub_offsets(live_entry)
        # A grouped entry is anything with more than one sub-pointer
        # in the live section — sub_offsets is the canonical source of
        # that information now. The legacy ``{j}``-in-text check still
        # covers hand-built entry dicts in older tests.
        is_grouped = len(live_offsets) > 1 or _has_join_marker(text) or _has_join_marker(live_text)
        if is_grouped:
            sub_texts = split_group_text(text)
            if len(sub_texts) != len(live_offsets):
                raise ValueError(
                    f"Translation index {index}: grouped entry has "
                    f"{len(sub_texts)} sub-strings but the live {context} "
                    f"has {len(live_offsets)}. Re-extract and merge."
                )
            if expand_groups:
                for live_off, sub in zip(live_offsets, sub_texts):
                    resolved.append((live_off, sub))
            else:
                resolved.append((live_offset, JOIN_MARKER.join(sub_texts)))
        else:
            resolved.append((live_offset, text))
    return resolved


def resolve_indexes_to_offsets(
    indexed: list[tuple[int, str]],
    file_data: bytes,
    config: dict,
) -> list[tuple[int, str]]:
    """
    Resolve ``(index, text)`` pairs to ``(offset, text)`` by re-extracting
    the live section's pointer table via a headers.json config.

    Thin wrapper around :func:`resolve_indexes_against_entries` that
    also handles the extraction step. Used by the xpath-driven
    ``import_from_csv`` / ``apply_translations_from_release_json``
    paths where the section's layout is described in ``headers.json``.
    Standalone file imports (FTXT, NPC dialogue, scenario, quest)
    call ``resolve_indexes_against_entries`` directly with entries
    produced by their format-specific extractors.

    :param indexed: List of ``(index, text)`` tuples
    :param file_data: Decrypted/decompressed binary data
    :param config: Extraction config dict from headers.json
    :return: List of ``(offset, text)`` tuples in the same order
    :raises ValueError: If any index is out of range for the section
    """
    from .common import extract_text_data_from_bytes

    entries = extract_text_data_from_bytes(file_data, config)
    return resolve_indexes_against_entries(indexed, entries, context="section")


def get_new_strings_auto(input_file: str) -> list[tuple[int, str]]:
    """
    Detect file format by extension and return new strings.

    :param input_file: Input file path (CSV or JSON)
    :return: New strings as list of (offset, string) tuples
    """
    if input_file.lower().endswith(".json"):
        return get_new_strings_from_json(input_file)
    return get_new_strings(input_file)


def append_to_binary(
    new_strings: list[tuple[int, str]],
    pointers_change: tuple[int, ...],
    output_file: str
) -> None:
    """
    Edit data in a binary file by appending to the end.

    :param new_strings: New strings to append as (offset, text) tuples
    :param pointers_change: Tuple of pointer offsets to change
    :param output_file: Binary file to edit
    :raises EncodingError: If a string cannot be encoded to Shift-JIS
    """
    with BinaryFile(output_file, "r+b") as bfile:
        for new_value, pointer_offset in zip(new_strings, pointers_change):
            # Append new string
            bfile.seek(0, os.SEEK_END)
            # Edit the pointer to the new position
            new_pointer = bfile.tell()
            encoded = encode_game_string(
                new_value[1],
                context=f"offset 0x{pointer_offset:x}"
            )
            bfile.write(encoded + b"\x00")

            bfile.seek(pointer_offset)
            logger.info("Assigned value %d at offset %d", new_pointer, pointer_offset)
            bfile.write_int(new_pointer)


# Legacy splitter — captures the embedded offset inside <join at="N">
# tags. Kept for backward compatibility so pre-1.6.0 translation files
# with stored offsets still parse. The new {j} marker is handled by
# ``split_group_text`` below, which drops offsets entirely because they
# are re-derived from the live pointer table at import time.
_JOIN_TAG_RE = re.compile(r'<join at="(\d+)">')
_JOIN_NEW_RE = re.compile(r'\{j\}')


def _has_join_marker(text: str) -> bool:
    """Return True if *text* contains any recognised grouped-entry marker."""
    return JOIN_MARKER in text or "<join at=" in text


def split_group_text(text: str) -> list[str]:
    """
    Split a grouped-entry text on any join marker form.

    Accepts both the new ``{j}`` marker and the legacy
    ``<join at="NNN">`` tag. Returns the sub-strings in order, without
    any offset information — callers that need offsets must align the
    result positionally against a freshly-extracted live entry.

    :param text: Translation text possibly containing join markers
    :return: Ordered list of sub-strings
    """
    return _JOIN_SPLIT_RE.split(text)


def parse_joined_text(offset: int, text: str) -> list[tuple[int, str]]:
    """
    Split a grouped-entry text into per-pointer pairs.

    Recognises both the new ``{j}`` marker (1.6.0+) and the legacy
    ``<join at="NNN">`` form. When the legacy form is used the embedded
    offset is preserved in the returned tuple. When the new marker is
    used only the first pair's offset is known (*offset*); subsequent
    sub-strings are returned with offset ``-1``, signalling to the
    caller that they must be re-derived from the live pointer table.

    :param offset: Pointer offset of the first sub-string
    :param text: Text that may contain join markers
    :return: List of ``(pointer_offset, sub_text)`` tuples. Sub-strings
        introduced by a ``{j}`` marker carry ``-1`` as their offset.
    """
    # Tokenise in a single pass so mixed forms (shouldn't happen but
    # cheap to support) still round-trip.
    result: list[tuple[int, str]] = []
    pos = 0
    first = True
    for match in re.finditer(r'<join at="(\d+)">|\{j\}', text):
        sub = text[pos:match.start()]
        if first:
            result.append((offset, sub))
            first = False
        else:
            # The previous match produced this segment; its offset was
            # recorded on the previous loop iteration.
            result[-1] = (result[-1][0], sub)
        # Seed the next segment's offset based on which marker we hit.
        if match.group(1) is not None:
            next_off = int(match.group(1))
        else:
            next_off = -1
        result.append((next_off, ""))
        pos = match.end()
    # Tail segment after the last marker (or the only segment if no
    # markers were present).
    tail = text[pos:]
    if first:
        result.append((offset, tail))
    else:
        result[-1] = (result[-1][0], tail)
    return result


def rebuild_section(
    file_data: bytes,
    config: dict,
    new_strings: list[tuple[int, str]],
    output_path: str
) -> str:
    """
    Rebuild a binary section with translations applied in-place.

    Instead of appending translated strings to the end of the file and
    leaving dead bytes behind, this function:

    1. Extracts ALL strings from the section (translated and untranslated)
    2. Writes them as a single contiguous block at EOF
    3. Updates ALL pointers to reference the new locations

    This produces a cleaner file with no orphaned string data.

    :param file_data: Decrypted/decompressed binary data
    :param config: Extraction config dict from headers.json
    :param new_strings: Translations from CSV as ``(offset, text)`` tuples
    :param output_path: Path for the output file
    :return: Path to the rebuilt file
    """
    from .common import extract_text_data_from_bytes

    # 1. Extract all entries from the section
    all_entries = extract_text_data_from_bytes(file_data, config)

    # 2. Index new_strings by their first (entry-level) offset. Grouped
    #    entries are stored as a list of sub-strings so we can align
    #    them positionally against the live entry at step 3 — this is
    #    what lets the ``{j}`` marker work even though it carries no
    #    per-sub ptr offset.
    group_translations: dict[int, list[str]] = {}
    single_translations: dict[int, str] = {}
    for offset, text in new_strings:
        if _has_join_marker(text):
            group_translations[offset] = split_group_text(text)
        else:
            single_translations[offset] = text

    # 3. Flatten all entries into (ptr_offset, text) pairs, applying
    #    translations where available. Per-sub slot offsets come from
    #    ``entry["sub_offsets"]`` (populated by every 1.6.0 extractor),
    #    and translations are aligned positionally against those
    #    offsets — no need to parse join tags out of the live text.
    all_pairs: list[tuple[int, str]] = []
    for entry in all_entries:
        entry_offset = int(entry["offset"])
        live_text = str(entry["text"])
        live_subs = split_group_text(live_text)
        live_offsets = _entry_sub_offsets(entry)

        if len(live_subs) != len(live_offsets):
            logger.warning(
                "Entry at 0x%x: %d sub-strings but %d sub_offsets. "
                "Falling back to entry offset.",
                entry_offset, len(live_subs), len(live_offsets),
            )
            live_offsets = [entry_offset] * len(live_subs)

        if entry_offset in group_translations and len(live_offsets) > 1:
            trans_subs = group_translations[entry_offset]
            if len(trans_subs) != len(live_offsets):
                logger.warning(
                    "Grouped entry at 0x%x: translation has %d sub-strings "
                    "but the live section has %d. Skipping and keeping "
                    "original strings — re-extract and merge the file.",
                    entry_offset, len(trans_subs), len(live_offsets),
                )
                for live_off, live_sub in zip(live_offsets, live_subs):
                    all_pairs.append((live_off, live_sub))
            else:
                for live_off, sub in zip(live_offsets, trans_subs):
                    all_pairs.append((live_off, sub))
        else:
            for live_off, live_sub in zip(live_offsets, live_subs):
                if live_off in single_translations:
                    all_pairs.append((live_off, single_translations[live_off]))
                else:
                    all_pairs.append((live_off, live_sub))

    # 4. Write file: copy original data, then append contiguous string block
    with open(output_path, "wb") as f:
        f.write(file_data)

    with BinaryFile(output_path, "r+b") as bfile:
        bfile.seek(0, os.SEEK_END)
        for ptr_offset, text in all_pairs:
            new_pointer = bfile.tell()
            encoded = encode_game_string(
                text, context=f"rebuild offset 0x{ptr_offset:x}"
            )
            bfile.write(encoded + b"\x00")
            # Save position, update pointer, restore position
            current_pos = bfile.tell()
            bfile.seek(ptr_offset)
            bfile.write_int(new_pointer)
            bfile.seek(current_pos)

    translated_count = (
        sum(len(subs) for subs in group_translations.values())
        + len(single_translations)
    )
    total_count = len(all_pairs)
    logger.info(
        "Rebuilt section: %d/%d strings translated, all %d pointers updated",
        translated_count, total_count, total_count
    )
    return output_path


def rebuild_ftxt(
    source_file: str,
    new_strings: list[tuple[int, str]],
    output_path: str
) -> str:
    """
    Rebuild an FTXT file with translated strings.

    FTXT strings are sequential (not pointer-based), so we rebuild the
    entire text block. Strings are identified by their byte offset in the
    original file.

    :param source_file: Path to the original FTXT file
    :param new_strings: List of (offset, new_text) tuples from CSV
    :param output_path: Path for the output file
    :return: Path to the rebuilt file
    """
    from .common import (
        load_file_data, is_ftxt_file, extract_ftxt_data,
        read_until_null, decode_game_string, FTXT_HEADER_SIZE, FTXT_MAGIC
    )

    file_data = load_file_data(source_file)

    if not is_ftxt_file(file_data):
        raise ValueError(f"'{source_file}' is not an FTXT file.")

    # Extract original strings with their offsets
    original_entries = extract_ftxt_data(file_data)

    # Build a mapping of offset → new text
    translation_map = {offset: text for offset, text in new_strings}

    # Rebuild text block with translations applied
    new_text_block = bytearray()
    for entry in original_entries:
        orig_offset = entry["offset"]
        if orig_offset in translation_map:
            text = translation_map[orig_offset]
        else:
            text = entry["text"]
        encoded = encode_game_string(text, context=f"FTXT offset 0x{orig_offset:x}")
        new_text_block.extend(encoded + b"\x00")

    # Rebuild file: header + new text block
    header = bytearray(file_data[:FTXT_HEADER_SIZE])
    # Update text block size in header
    struct.pack_into("<I", header, 0x0C, len(new_text_block))

    output_data = bytes(header) + bytes(new_text_block)

    with open(output_path, "wb") as f:
        f.write(output_data)

    logger.info("Rebuilt FTXT file: %d strings, %d bytes", len(original_entries), len(output_data))
    return output_path


DEFAULT_OUTPUT_DIR = "output"

# Maps the first component of a translation xpath to the game binary path
# relative to the game root directory (all binaries live under dat/).
XPATH_PREFIX_TO_GAME_FILE: dict[str, str] = {
    "dat": os.path.join("dat", "mhfdat.bin"),
    "pac": os.path.join("dat", "mhfpac.bin"),
    "inf": os.path.join("dat", "mhfinf.bin"),
    "jmp": os.path.join("dat", "mhfjmp.bin"),
    "nav": os.path.join("dat", "mhfnav.bin"),
    "gao": os.path.join("dat", "mhfgao.bin"),
    "rcc": os.path.join("dat", "mhfrcc.bin"),
    "msx": os.path.join("dat", "mhfmsx.bin"),
    "sqd": os.path.join("dat", "mhfsqd.bin"),
}


def apply_translations_from_release_json(
    json_file: str,
    lang: str,
    game_dir: str,
    compress: bool = True,
    encrypt: bool = True,
    key_index: int = DEFAULT_KEY_INDEX,
    headers_path: str = common.DEFAULT_HEADERS_PATH,
) -> dict[str, int]:
    """
    Apply translations from a MHFrontier-Translation release JSON to game files.

    The release JSON has the structure produced by the upstream exporter::

        {lang: {xpath: [entry, entry, ...]}}

    Each entry must have ``source`` and ``target``, plus **either**:

    * ``index`` — slot number in the section's pointer table (new
      index-keyed format, recommended; survives string-length shifts), or
    * ``location`` — legacy ``"0xNNN@filename.bin"`` offset string
      (still accepted for backward compatibility).

    Mixed sections are allowed: a section may use one format while another
    section in the same file uses the other.

    For each game binary that has at least one translated string this function:

    1. Reads the binary from *game_dir* (auto-decrypts / decompresses).
    2. Resolves any index-keyed entries against the live pointer table for
       their section.
    3. Appends all translated strings and updates the in-file pointers.
    4. Writes the result back, optionally re-compressing and re-encrypting.

    Only strings where *target* is non-empty and differs from *source* are
    applied. Sections whose game binary is missing from *game_dir* are skipped
    with a warning. Sections whose xpath is unknown to *headers_path* are
    skipped with a warning when they contain index-keyed entries (location
    entries don't need the config and are still applied).

    :param json_file: Path to the release JSON (e.g. ``translations-translated.json``).
    :param lang: Language code to apply (e.g. ``"fr"``).
    :param game_dir: Root directory of the game installation.
    :param compress: Re-compress with JKR HFI after patching.
    :param encrypt: Re-encrypt with ECD after patching.
    :param key_index: ECD key index (default 4, used by all MHF files).
    :param headers_path: Path to ``headers.json`` (used to resolve indexes).
    :return: Mapping of game-file relative path → number of strings applied.
    :raises ValueError: If *lang* is not present in the JSON.
    """
    import gzip
    import json as _json
    import tempfile

    with open(json_file, "rb") as f:
        raw = f.read()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    data = _json.loads(raw.decode("utf-8"))

    if lang not in data:
        available = list(data.keys())
        if not available:
            logger.info("No translations in %s (file may be empty)", json_file)
            return {}
        raise ValueError(
            f"Language '{lang}' not found in {json_file}. "
            f"Available: {', '.join(available)}"
        )

    # Collect entries grouped by target game file *and* by xpath, so that
    # index-keyed entries can be resolved against the right section's
    # pointer table later.
    #
    # Shape: {rel_path: {xpath: {"index": [(idx, text)], "offset": [(off, text)]}}}
    by_file: dict[str, dict[str, dict[str, list]]] = {}
    for xpath, strings in data[lang].items():
        prefix = xpath.split("/")[0]
        rel_path = XPATH_PREFIX_TO_GAME_FILE.get(prefix)
        if rel_path is None:
            logger.warning("Unknown xpath prefix '%s', skipping section '%s'", prefix, xpath)
            continue
        section = by_file.setdefault(rel_path, {}).setdefault(
            xpath, {"index": [], "offset": []}
        )
        for entry in strings:
            if not isinstance(entry, dict):
                continue
            target = entry.get("target") or ""
            source = entry.get("source") or ""
            if not target or target == source:
                continue
            # Rewrite CSV-form color codes ({cNN}/{/c}) back to the game's
            # ‾CNN bytes before re-encoding. Release JSONs produced from
            # MHFrontier-Translation store the brace form since 1.6.0, so
            # without this the braces would land in the binary as literal
            # text and the game would render them instead of colouring.
            target = color_codes_from_csv(target)
            if "index" in entry:
                try:
                    section["index"].append((int(entry["index"]), target))
                except (TypeError, ValueError):
                    logger.warning(
                        "Skipping entry in '%s': invalid index %r",
                        xpath, entry.get("index"),
                    )
            else:
                location = entry.get("location") or ""
                try:
                    section["offset"].append((parse_location(location), target))
                except CSVParseError as exc:
                    logger.warning("Skipping entry in '%s': %s", xpath, exc)

    results: dict[str, int] = {}

    for rel_path, sections in by_file.items():
        # Skip files where every section is empty after filtering
        if not any(sec["index"] or sec["offset"] for sec in sections.values()):
            continue

        game_path = os.path.join(game_dir, rel_path)
        if not os.path.exists(game_path):
            logger.warning("Game file not found, skipping: %s", game_path)
            continue

        with open(game_path, "rb") as fh:
            file_data = fh.read()

        was_encrypted = is_encrypted_file(file_data)
        was_compressed = False

        if was_encrypted:
            file_data, _ = decrypt(file_data)
            logger.info("  Auto-decrypted %s", rel_path)

        if is_jkr_file(file_data):
            was_compressed = True
            file_data = decompress_jkr(file_data)
            logger.info("  Auto-decompressed %s", rel_path)

        if was_encrypted and not encrypt:
            logger.warning(
                "  %s was encrypted but --encrypt not set — output will NOT be game-ready",
                rel_path,
            )
        if was_compressed and not compress:
            logger.warning(
                "  %s was compressed but --compress not set — output will NOT be game-ready",
                rel_path,
            )

        # Resolve all sections to flat (offset, text) pairs against the
        # now-decrypted file_data. Grouped entries (``{j}`` marker or
        # legacy ``<join at="N">`` tags) must be expanded into per-sub
        # ``(live_ptr_offset, sub_text)`` pairs so ``append_to_binary``
        # updates every sibling pointer — otherwise only the first
        # pointer moves and the rest keep referencing stale strings.
        all_strings: list[tuple[int, str]] = []
        for xpath, section in sections.items():
            # Location-keyed entries: expand legacy ``<join at="N">``
            # tags directly (their embedded offsets are the target ptr
            # offsets). ``{j}``-form entries would need a live config
            # to re-derive offsets; try to load one, and skip the
            # section with a warning if it isn't in headers.json.
            loc_entries = section["offset"]
            needs_live_expansion = any(
                JOIN_MARKER in t for _, t in loc_entries
            )
            if needs_live_expansion:
                try:
                    loc_config = common.read_extraction_config(
                        xpath, headers_path,
                    )
                except KeyError:
                    logger.warning(
                        "  Skipping %d location entr(y/ies) in '%s': "
                        "xpath not found in %s (needed to resolve "
                        "'{j}' markers)",
                        len(loc_entries), xpath, headers_path,
                    )
                    loc_entries = []
                else:
                    try:
                        loc_entries = resolve_offsets_with_groups(
                            loc_entries, file_data, loc_config,
                        )
                    except ValueError as exc:
                        logger.warning(
                            "  Skipping location entries in '%s': %s",
                            xpath, exc,
                        )
                        loc_entries = []
            else:
                # Legacy tags carry their own offsets — parse_joined_text
                # expands them without needing a live config.
                loc_entries = _expand_legacy_join_tags(loc_entries)
            all_strings.extend(loc_entries)

            if not section["index"]:
                continue
            try:
                config = common.read_extraction_config(xpath, headers_path)
            except KeyError:
                logger.warning(
                    "  Skipping %d indexed entr(y/ies) in '%s': "
                    "xpath not found in %s",
                    len(section["index"]), xpath, headers_path,
                )
                continue
            try:
                all_strings.extend(
                    resolve_indexes_to_offsets(section["index"], file_data, config)
                )
            except ValueError as exc:
                logger.warning(
                    "  Skipping indexed entries in '%s': %s", xpath, exc,
                )

        if not all_strings:
            continue

        logger.info("Applying %d translation(s) to %s", len(all_strings), rel_path)

        # Write decrypted/decompressed data to a temp file, apply translations,
        # then read back for the compress/encrypt pass.
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            tmp.write(file_data)
            tmp_path = tmp.name

        try:
            pointers = tuple(offset for offset, _ in all_strings)
            append_to_binary(all_strings, pointers, tmp_path)
            with open(tmp_path, "rb") as fh:
                result_data = fh.read()
        finally:
            os.unlink(tmp_path)

        if compress:
            result_data = compress_jkr_hfi(result_data)
            logger.info("  Compressed %s", rel_path)

        if encrypt:
            result_data = encode_ecd(result_data, key_index=key_index)
            logger.info("  Encrypted %s (key %d)", rel_path, key_index)

        with open(game_path, "wb") as fh:
            fh.write(result_data)

        results[rel_path] = len(all_strings)
        logger.info("  ✓ %d string(s) applied → %s", len(all_strings), game_path)

    return results


def import_from_csv(
    input_file: str,
    output_file: str,
    output_path: Optional[str] = None,
    compress: bool = False,
    encrypt: bool = False,
    key_index: int = DEFAULT_KEY_INDEX,
    xpath: Optional[str] = None,
    headers_path: str = common.DEFAULT_HEADERS_PATH,
    fold_unsupported_chars: bool = False,
) -> Optional[str]:
    """
    Use the CSV file to edit the binary file.

    When *xpath* is provided, uses :func:`rebuild_section` to rewrite
    the entire string section in-place (all pointers updated, no dead
    bytes).  Without *xpath*, falls back to the legacy append strategy.

    :param input_file: Path to CSV file with translations
    :param output_file: Path to source binary file
    :param output_path: Path for the modified binary file. If None, uses
        '{output_dir}/{basename}-modified.bin' where basename is derived from output_file.
    :param compress: If True, compress the output using JKR HFI compression
    :param encrypt: If True, encrypt the output using ECD encryption
    :param key_index: ECD key index to use (0-5). Default is 4.
    :param xpath: Optional xpath to the section in headers.json.  When
        provided, enables in-place rebuild instead of append.
    :param headers_path: Path to headers.json (default: headers.json)
    :param fold_unsupported_chars: If True, fold characters that the
        MHFrontier custom font cannot render (Latin diacritics, ligatures,
        typographic punctuation) down to their nearest ASCII equivalents
        before encoding. Off by default to keep Japanese imports
        byte-identical. Translators of European languages should pass
        ``True`` until the in-game font is extended.
        See :mod:`src.text_folding` for the exact mapping.
    :return: Path to the modified binary file, or None if no changes
    """
    # Validate xpath early to give a clear error instead of a confusing KeyError
    if xpath is not None:
        try:
            common.read_extraction_config(xpath, headers_path)
        except KeyError:
            available = common.get_all_xpaths(headers_path)
            raise ValueError(
                f"xpath '{xpath}' not found in {headers_path}. "
                f"Available xpaths: {', '.join(available[:10])}"
                + (f" ... ({len(available)} total)" if len(available) > 10 else "")
            )

    fmt = detect_translation_format(input_file)
    # When a translation file is index-keyed we need to know the section's
    # layout to resolve slot→offset. Prefer an explicit --xpath, fall back
    # to the filename/metadata-based inference, and if that still fails
    # peek at the source binary: standalone quest files don't live in
    # headers.json but have their own extractor, so we detect them here
    # and handle their indexed imports via the quest-file branch of the
    # legacy-append path further down.
    indexed_standalone_quest = False
    if fmt == "index":
        if xpath is None:
            inferred = infer_xpath(input_file, headers_path)
            if inferred is None:
                # Last resort: is the source a standalone quest file?
                try:
                    with open(output_file, "rb") as _fh:
                        _probe = _fh.read()
                    _probe_data = _probe
                    if is_encrypted_file(_probe_data):
                        _probe_data, _ = decrypt(_probe_data)
                    if is_jkr_file(_probe_data):
                        _probe_data = decompress_jkr(_probe_data)
                    common.extract_quest_file_data(_probe_data)
                    indexed_standalone_quest = True
                except (ValueError, common.EncodingError, OSError):
                    raise ValueError(
                        f"'{input_file}' uses index-based locations and no "
                        "xpath could be inferred from its metadata or filename. "
                        "Pass --xpath=<section> explicitly."
                    )
            else:
                xpath = inferred
                logger.info("Inferred xpath '%s' from %s", xpath, input_file)
        indexed_strings = get_new_strings_indexed(input_file)
        logger.info(
            "Found %d translations to write (index-based)", len(indexed_strings)
        )
        if not indexed_strings:
            logger.info("No translations to write, skipping binary modification")
            return None
        if fold_unsupported_chars:
            from .text_folding import fold_unsupported_chars as _fold
            indexed_strings = [(idx, _fold(text)) for idx, text in indexed_strings]
            logger.info(
                "Folded unsupported characters in %d translations "
                "(custom-font workaround)",
                len(indexed_strings),
            )
    else:
        new_strings = get_new_strings_auto(input_file)
        logger.info("Found %d translations to write", len(new_strings))
        if not new_strings:
            logger.info("No translations to write, skipping binary modification")
            return None
        if fold_unsupported_chars:
            from .text_folding import fold_unsupported_chars as _fold
            new_strings = [(loc, _fold(text)) for loc, text in new_strings]
            logger.info(
                "Folded unsupported characters in %d translations "
                "(custom-font workaround)",
                len(new_strings),
            )

    if output_path is None:
        # Generate default output path
        basename = os.path.splitext(os.path.basename(output_file))[0]
        output_path = os.path.join(DEFAULT_OUTPUT_DIR, f"{basename}-modified.bin")

    # Ensure output directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info("Created output directory '%s'", output_dir)

    # Read source file and auto-decrypt/decompress before modification
    with open(output_file, "rb") as f:
        file_data = f.read()

    was_encrypted = is_encrypted_file(file_data)
    was_compressed = False

    if was_encrypted:
        file_data, _ = decrypt(file_data)
        logger.info("Auto-decrypted source file")

    if is_jkr_file(file_data):
        was_compressed = True
        file_data = decompress_jkr(file_data)
        logger.info("Auto-decompressed source file")

    # Warn if source had layers that won't be restored
    if was_encrypted and not encrypt:
        logger.warning(
            "Source file was encrypted but --encrypt was not specified. "
            "Output will NOT be game-ready. Add --encrypt to produce a usable file."
        )
    if was_compressed and not compress:
        logger.warning(
            "Source file was compressed but --compress was not specified. "
            "Output will NOT be game-ready. Add --compress to produce a usable file."
        )

    if indexed_standalone_quest:
        # Standalone quest file with an indexed CSV/JSON: resolve the
        # slot numbers against a fresh quest extraction and fall
        # through to the legacy append path, which already knows how
        # to update grouped quest pointers.
        quest_entries = common.extract_quest_file_data(file_data)
        new_strings = resolve_indexes_against_entries(
            indexed_strings, quest_entries, context="quest file",
        )

    if xpath is not None:
        config = common.read_extraction_config(xpath, headers_path)
        if fmt == "index":
            # Fingerprint sanity check: warn loudly if the translation file
            # was extracted from a binary that doesn't match the target.
            recorded_fp = read_json_metadata(input_file).get("fingerprint")
            if recorded_fp:
                actual_fp = common.compute_binary_fingerprint(file_data)
                if actual_fp != recorded_fp:
                    logger.warning(
                        "Binary fingerprint mismatch: '%s' was extracted from a "
                        "binary with fingerprint %s but the target binary has "
                        "fingerprint %s. This may indicate a different game "
                        "version, a different patch level, or a binary that "
                        "already has translations applied. Indexes may not "
                        "refer to the same strings — proceed with caution.",
                        input_file, recorded_fp, actual_fp,
                    )
                else:
                    logger.info(
                        "Binary fingerprint %s matches translation source",
                        actual_fp,
                    )
            new_strings = resolve_indexes_to_offsets(
                indexed_strings, file_data, config
            )
        rebuild_section(file_data, config, new_strings, output_path)
        logger.info("Rebuilt section '%s' in %s", xpath, output_path)
    else:
        # Legacy append strategy (backward compatible).
        #
        # The append path can only update ptr offsets it knows about.
        # For grouped entries that's only possible with the legacy
        # ``<join at="N">`` form, which carries per-sub ptr offsets
        # inline. The new ``{j}`` marker has no offsets — those have
        # to come from a live re-extraction. Without --xpath the only
        # format we can re-extract here is a standalone quest file, so
        # try that first and fall back to an error if it doesn't look
        # like one.
        has_new_marker = any(JOIN_MARKER in text for _, text in new_strings)
        if has_new_marker:
            try:
                quest_entries = common.extract_quest_file_data(file_data)
            except (ValueError, common.EncodingError):
                quest_entries = None
            if not quest_entries:
                raise ValueError(
                    "CSV/JSON contains the grouped-entry marker '{j}' "
                    "(1.6.0 format) but no --xpath was given and the "
                    "source file is not a standalone quest file. Pass "
                    "--xpath=<section> so rebuild_section can re-derive "
                    "sibling pointer offsets from the live pointer table."
                )
            # Resolve {j}-form entries against the live quest table by
            # positional alignment, then fall through to the regular
            # append path with concrete (offset, text) pairs.
            quest_by_first_off = {
                int(e["offset"]): _entry_sub_offsets(e)
                for e in quest_entries
            }
            resolved_new: list[tuple[int, str]] = []
            for offset, text in new_strings:
                if JOIN_MARKER not in text and "<join at=" not in text:
                    resolved_new.append((offset, text))
                    continue
                live_offsets = quest_by_first_off.get(offset)
                if live_offsets is None:
                    raise ValueError(
                        f"Grouped translation at offset 0x{offset:x} does "
                        f"not match any quest entry in the source file "
                        f"(available entry offsets: "
                        f"{[hex(k) for k in quest_by_first_off]})"
                    )
                subs = split_group_text(text)
                if len(subs) != len(live_offsets):
                    raise ValueError(
                        f"Grouped entry at 0x{offset:x}: translation has "
                        f"{len(subs)} sub-strings but the live quest "
                        f"entry has {len(live_offsets)}. Re-extract and "
                        f"merge the translation file."
                    )
                for live_off, sub in zip(live_offsets, subs):
                    resolved_new.append((live_off, sub))
            new_strings = resolved_new

        # Expand legacy <join at="N"> tags so each sub-pointer is
        # updated independently — otherwise grouped sections like
        # inf/quests would write the literal join markup as a single
        # string and leave sibling pointers stale.
        expanded: list[tuple[int, str]] = []
        has_joins = False
        for offset, text in new_strings:
            pairs = parse_joined_text(offset, text)
            if len(pairs) > 1:
                has_joins = True
            expanded.extend(pairs)
        if has_joins:
            logger.warning(
                "CSV contains <join at=...> tags (grouped pointer entries) "
                "but no --xpath was given. Falling back to append mode; "
                "prefer --xpath=<section> so rebuild_section is used and "
                "orphan pointers are avoided."
            )
        pointers_to_update = [offset for offset, _ in expanded]
        with open(output_path, "wb") as f:
            f.write(file_data)
        append_to_binary(expanded, tuple(pointers_to_update), output_path)
        logger.info("Wrote output to %s (append mode)", output_path)

    if compress:
        # Read the modified file and compress it
        with open(output_path, "rb") as f:
            data = f.read()
        compressed = compress_jkr_hfi(data)
        with open(output_path, "wb") as f:
            f.write(compressed)
        logger.info(
            "Compressed output: %d bytes -> %d bytes (%.1f%% reduction)",
            len(data), len(compressed),
            (1 - len(compressed) / len(data)) * 100 if data else 0
        )

    if encrypt:
        # Read the (potentially compressed) file and encrypt it
        with open(output_path, "rb") as f:
            data = f.read()
        encrypted_data = encode_ecd(data, key_index=key_index)
        with open(output_path, "wb") as f:
            f.write(encrypted_data)
        logger.info(
            "Encrypted output with ECD (key index %d): %d bytes -> %d bytes",
            key_index, len(data), len(encrypted_data)
        )

    return output_path


def _read_standalone_translations(
    input_file: str,
    live_entries_fn,
    context: str,
) -> list[tuple[int, str]]:
    """
    Read translations for a standalone-format file (FTXT, NPC dialogue,
    scenario, quest) and return resolved ``(offset, text)`` pairs.

    Auto-detects the CSV/JSON format (``index`` vs legacy ``location``)
    and dispatches accordingly:

    - **Index-keyed** (1.6.0 default): load the (index, text) pairs via
      :func:`get_new_strings_indexed`, then resolve them against the
      entries returned by *live_entries_fn()* using
      :func:`resolve_indexes_against_entries`. This gives
      format-specific standalone imports the same positional-alignment
      behaviour that headers.json-backed sections get through
      :func:`resolve_indexes_to_offsets`.
    - **Legacy offset-keyed**: load via :func:`get_new_strings_auto`.
      The entries already carry live ptr offsets; no re-extraction
      needed.

    :param input_file: Path to the translation CSV/JSON.
    :param live_entries_fn: Zero-arg callable that re-extracts the
        source binary and returns ``list[dict]`` of live entries
        (each with ``offset`` / ``text``). Called at most once, and
        only when the translation file is index-keyed.
    :param context: Short label for error messages (e.g. ``"FTXT"``).
    :return: Resolved ``(offset, text)`` pairs ready to hand to the
        format's ``rebuild_*`` function.
    """
    fmt = detect_translation_format(input_file)
    if fmt == "index":
        indexed = get_new_strings_indexed(input_file)
        if not indexed:
            return []
        # Keep grouped entries joined: the standalone rebuild_*
        # functions key their translation map by entry-level offset
        # and call split_join_text on the text themselves, so a
        # single ``(entry_offset, "a{j}b{j}c")`` pair is exactly the
        # shape they expect.
        return resolve_indexes_against_entries(
            indexed, live_entries_fn(),
            context=context, expand_groups=False,
        )
    return get_new_strings_auto(input_file)


def import_ftxt_from_csv(
    input_file: str,
    output_file: str,
    output_path: Optional[str] = None,
    compress: bool = False,
    encrypt: bool = False,
    key_index: int = DEFAULT_KEY_INDEX
) -> Optional[str]:
    """
    Import translations from CSV into an FTXT file.

    FTXT strings are sequential (not pointer-based), so the text block
    is rebuilt entirely rather than using the append strategy.

    Accepts both index-keyed (1.6.0 default) and legacy offset-keyed
    CSV/JSON. Index-keyed files are resolved against a fresh
    re-extraction of *output_file* via :func:`_read_standalone_translations`.

    :param input_file: Path to CSV file with translations
    :param output_file: Path to source FTXT binary file
    :param output_path: Path for the modified file. If None, auto-generated.
    :param compress: If True, compress output with JKR HFI
    :param encrypt: If True, encrypt output with ECD
    :param key_index: ECD key index (0-5, default 4)
    :return: Path to the modified file, or None if no changes
    """
    from .common import load_file_data, extract_ftxt_data

    def _live_entries():
        return extract_ftxt_data(load_file_data(output_file))

    new_strings = _read_standalone_translations(
        input_file, _live_entries, context="FTXT",
    )
    logger.info("Found %d translations to write", len(new_strings))

    if not new_strings:
        logger.info("No translations to write, skipping FTXT modification")
        return None

    if output_path is None:
        basename = os.path.splitext(os.path.basename(output_file))[0]
        output_path = os.path.join(DEFAULT_OUTPUT_DIR, f"{basename}-modified.bin")

    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    rebuild_ftxt(output_file, new_strings, output_path)

    if compress:
        with open(output_path, "rb") as f:
            data = f.read()
        compressed = compress_jkr_hfi(data)
        with open(output_path, "wb") as f:
            f.write(compressed)
        logger.info(
            "Compressed FTXT output: %d -> %d bytes",
            len(data), len(compressed)
        )

    if encrypt:
        with open(output_path, "rb") as f:
            data = f.read()
        encrypted_data = encode_ecd(data, key_index=key_index)
        with open(output_path, "wb") as f:
            f.write(encrypted_data)
        logger.info("Encrypted FTXT output with ECD (key %d)", key_index)

    return output_path


def rebuild_npc_dialogue(
    source_file: str,
    new_strings: list[tuple[int, str]],
    output_path: str
) -> str:
    """
    Rebuild an NPC dialogue binary with translated strings.

    The NPC dialogue format uses internal relative pointers, so the entire
    binary is rebuilt from scratch rather than appending.

    :param source_file: Path to the original dialogue file
    :param new_strings: List of (offset, new_text) tuples from CSV
    :param output_path: Path for the output file
    :return: Path to the rebuilt file
    """
    from .common import (
        load_file_data, extract_npc_dialogue_data,
        split_join_text, encode_game_string
    )

    file_data = load_file_data(source_file)
    original_entries = extract_npc_dialogue_data(file_data)

    # Build translation map: {table_offset: translated_text}
    translation_map: dict[int, str] = {}
    for offset, text in new_strings:
        translation_map[offset] = text

    # Parse the NPC table to get NPC IDs
    npc_ids: list[int] = []
    pos = 0
    while pos + 8 <= len(file_data):
        npc_id = struct.unpack_from("<I", file_data, pos)[0]
        block_ptr = struct.unpack_from("<I", file_data, pos + 4)[0]
        if npc_id == 0xFFFFFFFF and block_ptr == 0xFFFFFFFF:
            break
        npc_ids.append(npc_id)
        pos += 8

    # Reconstruct binary
    # 1. NPC table: (npc_id, block_pointer) × N + terminator
    num_npcs = len(npc_ids)
    npc_table_size = (num_npcs + 1) * 8  # +1 for terminator
    blocks_start = npc_table_size

    # 2. Build per-NPC blocks with translated strings
    npc_blocks: list[bytes] = []
    for i, entry in enumerate(original_entries):
        table_offset = entry["offset"]
        if table_offset in translation_map:
            text = translation_map[table_offset]
        else:
            text = entry["text"]

        # Split join tags to get individual dialogue strings
        dialogues = split_join_text(text)

        if not dialogues or (len(dialogues) == 1 and dialogues[0] == ""):
            # Empty NPC: just header_size = 0
            npc_blocks.append(struct.pack("<I", 0))
            continue

        num_dialogues = len(dialogues)
        header_size = num_dialogues * 4

        # Encode strings
        encoded_strings: list[bytes] = []
        for dlg in dialogues:
            encoded_strings.append(encode_game_string(dlg) + b"\x00")

        # Calculate relative pointers from block start
        # Block layout: header_size(4) + pointers(N*4) + strings
        pointers_section_size = 4 + num_dialogues * 4
        string_offset = pointers_section_size
        relative_ptrs: list[int] = []
        for enc in encoded_strings:
            relative_ptrs.append(string_offset)
            string_offset += len(enc)

        # Build block
        block = bytearray()
        block.extend(struct.pack("<I", header_size))
        for rp in relative_ptrs:
            block.extend(struct.pack("<I", rp))
        for enc in encoded_strings:
            block.extend(enc)
        npc_blocks.append(bytes(block))

    # 3. Compute block offsets
    block_offsets: list[int] = []
    current_offset = blocks_start
    for block in npc_blocks:
        block_offsets.append(current_offset)
        current_offset += len(block)

    # 4. Write NPC table
    output = bytearray()
    for i, npc_id in enumerate(npc_ids):
        output.extend(struct.pack("<I", npc_id))
        output.extend(struct.pack("<I", block_offsets[i]))
    # Terminator
    output.extend(struct.pack("<I", 0xFFFFFFFF))
    output.extend(struct.pack("<I", 0xFFFFFFFF))

    # 5. Write blocks
    for block in npc_blocks:
        output.extend(block)

    with open(output_path, "wb") as f:
        f.write(bytes(output))

    logger.info(
        "Rebuilt NPC dialogue: %d NPCs, %d bytes",
        num_npcs, len(output)
    )
    return output_path


def rebuild_scenario_file(
    source_file: str,
    new_strings: list[tuple[int, str]],
    output_path: str
) -> str:
    """
    Rebuild a scenario file with translated strings.

    Preserves the container structure (chunk sizes, metadata) and replaces
    only the string bytes within each chunk.

    :param source_file: Path to the original scenario file
    :param new_strings: List of (offset, new_text) tuples from CSV
    :param output_path: Path for the output file
    :return: Path to the rebuilt file
    """
    from .common import load_file_data, encode_game_string
    from .scenario import extract_scenario_file_data

    file_data = load_file_data(source_file)
    original_entries = extract_scenario_file_data(file_data)

    # Build translation map
    translation_map: dict[int, str] = {}
    for offset, text in new_strings:
        translation_map[offset] = text

    # Rebuild: copy original file, then overwrite strings in-place
    # Since strings are null-terminated and replacements may differ in length,
    # we write the whole file then patch each string location
    output_data = bytearray(file_data)

    for entry in original_entries:
        offset = entry["offset"]
        if offset in translation_map:
            new_text = translation_map[offset]
        else:
            new_text = entry["text"]

        # Encode new string
        encoded = encode_game_string(
            new_text, context=f"scenario rebuild offset 0x{offset:x}"
        )

        old_text = entry["text"]
        old_encoded = encode_game_string(
            old_text, context=f"scenario original offset 0x{offset:x}"
        )

        if len(encoded) <= len(old_encoded):
            # Fits in place: write + null-pad remainder
            output_data[offset:offset + len(encoded)] = encoded
            output_data[offset + len(encoded)] = 0x00
            # Null-pad any extra bytes from old string
            for i in range(len(encoded) + 1, len(old_encoded) + 1):
                if offset + i < len(output_data):
                    output_data[offset + i] = 0x00
        else:
            # Doesn't fit: write truncated to original length
            # This is a limitation — scenario files have fixed chunk sizes
            max_len = len(old_encoded)
            output_data[offset:offset + max_len] = encoded[:max_len]
            output_data[offset + max_len] = 0x00
            logger.warning(
                "String at 0x%x truncated: %d bytes -> %d bytes max",
                offset, len(encoded), max_len
            )

    with open(output_path, "wb") as f:
        f.write(bytes(output_data))

    translated_count = sum(1 for e in original_entries if e["offset"] in translation_map)
    logger.info(
        "Rebuilt scenario file: %d/%d strings translated",
        translated_count, len(original_entries)
    )
    return output_path


def import_scenario_from_csv(
    input_file: str,
    output_file: str,
    output_path: Optional[str] = None,
    compress: bool = False,
    encrypt: bool = False,
    key_index: int = DEFAULT_KEY_INDEX
) -> Optional[str]:
    """
    Import translations from CSV into a scenario file.

    Accepts both index-keyed (1.6.0 default) and legacy offset-keyed
    CSV/JSON. Index-keyed files are resolved against a fresh
    re-extraction of *output_file* via :func:`_read_standalone_translations`.

    :param input_file: Path to CSV file with translations
    :param output_file: Path to source scenario binary file
    :param output_path: Path for the modified file. If None, auto-generated.
    :param compress: If True, compress output with JKR HFI
    :param encrypt: If True, encrypt output with ECD
    :param key_index: ECD key index (0-5, default 4)
    :return: Path to the modified file, or None if no changes
    """
    from .scenario import extract_scenario_file

    def _live_entries():
        return extract_scenario_file(output_file)

    new_strings = _read_standalone_translations(
        input_file, _live_entries, context="scenario",
    )
    logger.info("Found %d scenario translations to write", len(new_strings))

    if not new_strings:
        logger.info("No translations to write, skipping scenario modification")
        return None

    if output_path is None:
        basename = os.path.splitext(os.path.basename(output_file))[0]
        output_path = os.path.join(DEFAULT_OUTPUT_DIR, f"{basename}-modified.bin")

    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    rebuild_scenario_file(output_file, new_strings, output_path)

    if compress:
        with open(output_path, "rb") as f:
            data = f.read()
        compressed = compress_jkr_hfi(data)
        with open(output_path, "wb") as f:
            f.write(compressed)
        logger.info(
            "Compressed scenario output: %d -> %d bytes",
            len(data), len(compressed)
        )

    if encrypt:
        with open(output_path, "rb") as f:
            data = f.read()
        encrypted_data = encode_ecd(data, key_index=key_index)
        with open(output_path, "wb") as f:
            f.write(encrypted_data)
        logger.info("Encrypted scenario output with ECD (key %d)", key_index)

    return output_path


def import_npc_dialogue_from_csv(
    input_file: str,
    output_file: str,
    output_path: Optional[str] = None,
    compress: bool = False,
    encrypt: bool = False,
    key_index: int = DEFAULT_KEY_INDEX
) -> Optional[str]:
    """
    Import translations from CSV into an NPC dialogue file.

    NPC dialogue uses internal relative pointers, so the binary is
    fully rebuilt rather than using the append strategy.

    Accepts both index-keyed (1.6.0 default) and legacy offset-keyed
    CSV/JSON. Index-keyed files are resolved against a fresh
    re-extraction of *output_file* via :func:`_read_standalone_translations`.

    :param input_file: Path to CSV file with translations
    :param output_file: Path to source NPC dialogue binary file
    :param output_path: Path for the modified file. If None, auto-generated.
    :param compress: If True, compress output with JKR HFI
    :param encrypt: If True, encrypt output with ECD
    :param key_index: ECD key index (0-5, default 4)
    :return: Path to the modified file, or None if no changes
    """
    from .common import load_file_data, extract_npc_dialogue_data

    def _live_entries():
        return extract_npc_dialogue_data(load_file_data(output_file))

    new_strings = _read_standalone_translations(
        input_file, _live_entries, context="NPC dialogue",
    )
    logger.info("Found %d NPC dialogue translations to write", len(new_strings))

    if not new_strings:
        logger.info("No translations to write, skipping NPC dialogue modification")
        return None

    if output_path is None:
        basename = os.path.splitext(os.path.basename(output_file))[0]
        output_path = os.path.join(DEFAULT_OUTPUT_DIR, f"{basename}-modified.bin")

    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    rebuild_npc_dialogue(output_file, new_strings, output_path)

    if compress:
        with open(output_path, "rb") as f:
            data = f.read()
        compressed = compress_jkr_hfi(data)
        with open(output_path, "wb") as f:
            f.write(compressed)
        logger.info(
            "Compressed NPC dialogue output: %d -> %d bytes",
            len(data), len(compressed)
        )

    if encrypt:
        with open(output_path, "rb") as f:
            data = f.read()
        encrypted_data = encode_ecd(data, key_index=key_index)
        with open(output_path, "wb") as f:
            f.write(encrypted_data)
        logger.info("Encrypted NPC dialogue output with ECD (key %d)", key_index)

    return output_path
