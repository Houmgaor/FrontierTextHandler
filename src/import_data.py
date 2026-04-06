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
from .common import encode_game_string, EncodingError
from .jkr_decompress import is_jkr_file, decompress_jkr
from .jkr_compress import compress_jkr_hfi
from .crypto import is_encrypted_file, decrypt, encode_ecd, DEFAULT_KEY_INDEX

logger = logging.getLogger(__name__)


class CSVParseError(ValueError):
    """Raised when CSV parsing fails due to malformed data."""
    pass


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
                new_strings.append((index, line[2]))
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
                new_strings.append((index, entry["target"]))
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
                pairs.append((int(entry["index"]), entry["target"]))
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
                pairs.append((int(row["index"]), row["target"]))
            except ValueError as exc:
                logger.warning("Line %d: invalid index %r: %s", line_num, row.get("index"), exc)
    return pairs


def resolve_indexes_to_offsets(
    indexed: list[tuple[int, str]],
    file_data: bytes,
    config: dict,
) -> list[tuple[int, str]]:
    """
    Resolve ``(index, text)`` pairs to ``(offset, text)`` by re-extracting
    the live section's pointer table.

    :param indexed: List of ``(index, text)`` tuples
    :param file_data: Decrypted/decompressed binary data
    :param config: Extraction config dict from headers.json
    :return: List of ``(offset, text)`` tuples in the same order
    :raises ValueError: If any index is out of range for the section
    """
    from .common import extract_text_data_from_bytes

    entries = extract_text_data_from_bytes(file_data, config)
    resolved: list[tuple[int, str]] = []
    for index, text in indexed:
        if index < 0 or index >= len(entries):
            raise ValueError(
                f"Translation index {index} is out of range for section "
                f"with {len(entries)} entries. The section may have shrunk; "
                f"re-extract and merge translations to update the file."
            )
        resolved.append((entries[index]["offset"], text))
    return resolved


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


_JOIN_TAG_RE = re.compile(r'<join at="(\d+)">')


def parse_joined_text(offset: int, text: str) -> list[tuple[int, str]]:
    """
    Split a text with ``<join at="NNN">`` tags into per-pointer pairs.

    A single CSV entry may map to multiple pointers when the extraction
    grouped them with join tags.  This function expands them back.

    :param offset: Pointer offset of the first string (from CSV location)
    :param text: Text that may contain ``<join at="NNN">`` tags
    :return: List of ``(pointer_offset, sub_text)`` tuples
    """
    parts = _JOIN_TAG_RE.split(text)
    # parts[0] is the first text, then alternating (offset_str, text)
    result = [(offset, parts[0])]
    for i in range(1, len(parts), 2):
        join_offset = int(parts[i])
        join_text = parts[i + 1]
        result.append((join_offset, join_text))
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

    # 2. Build translation map: {pointer_offset: new_text}
    #    Expand join tags so each sub-pointer maps independently
    translation_map: dict[int, str] = {}
    for offset, text in new_strings:
        for ptr_offset, sub_text in parse_joined_text(offset, text):
            translation_map[ptr_offset] = sub_text

    # 3. Flatten all entries into (ptr_offset, text) pairs,
    #    applying translations where available
    all_pairs: list[tuple[int, str]] = []
    for entry in all_entries:
        for ptr_offset, sub_text in parse_joined_text(entry["offset"], entry["text"]):
            if ptr_offset in translation_map:
                all_pairs.append((ptr_offset, translation_map[ptr_offset]))
            else:
                all_pairs.append((ptr_offset, sub_text))

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

    translated_count = len(translation_map)
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
) -> dict[str, int]:
    """
    Apply translations from a MHFrontier-Translation release JSON to game files.

    The release JSON has the structure produced by ``export_json.py``::

        {lang: {xpath: [{location, source, target}]}}

    For each game binary that has at least one translated string this function:

    1. Reads the binary from *game_dir* (auto-decrypts / decompresses).
    2. Appends all translated strings and updates the in-file pointers.
    3. Writes the result back, optionally re-compressing and re-encrypting.

    Only strings where *target* is non-empty and differs from *source* are
    applied.  Sections whose game binary is missing from *game_dir* are skipped
    with a warning.

    :param json_file: Path to the release JSON (e.g. ``translations-translated.json``).
    :param lang: Language code to apply (e.g. ``"fr"``).
    :param game_dir: Root directory of the game installation.
    :param compress: Re-compress with JKR HFI after patching.
    :param encrypt: Re-encrypt with ECD after patching.
    :param key_index: ECD key index (default 4, used by all MHF files).
    :return: Mapping of game-file relative path → number of strings applied.
    :raises ValueError: If *lang* is not present in the JSON.
    """
    import json as _json
    import tempfile

    with open(json_file, "r", encoding="utf-8") as f:
        data = _json.load(f)

    if lang not in data:
        available = list(data.keys())
        if not available:
            logger.info("No translations in %s (file may be empty)", json_file)
            return {}
        raise ValueError(
            f"Language '{lang}' not found in {json_file}. "
            f"Available: {', '.join(available)}"
        )

    # Collect (offset, text) pairs grouped by target game file.
    by_file: dict[str, list[tuple[int, str]]] = {}
    for xpath, strings in data[lang].items():
        prefix = xpath.split("/")[0]
        rel_path = XPATH_PREFIX_TO_GAME_FILE.get(prefix)
        if rel_path is None:
            logger.warning("Unknown xpath prefix '%s', skipping section '%s'", prefix, xpath)
            continue
        pairs = by_file.setdefault(rel_path, [])
        for entry in strings:
            if not isinstance(entry, dict):
                continue
            target = entry.get("target") or ""
            source = entry.get("source") or ""
            if not target or target == source:
                continue
            location = entry.get("location") or ""
            try:
                offset = parse_location(location)
                pairs.append((offset, target))
            except CSVParseError as exc:
                logger.warning("Skipping entry in '%s': %s", xpath, exc)

    results: dict[str, int] = {}

    for rel_path, all_strings in by_file.items():
        if not all_strings:
            continue

        game_path = os.path.join(game_dir, rel_path)
        if not os.path.exists(game_path):
            logger.warning("Game file not found, skipping: %s", game_path)
            continue

        logger.info("Applying %d translation(s) to %s", len(all_strings), rel_path)

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
    headers_path: str = common.DEFAULT_HEADERS_PATH
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
    if fmt == "index":
        if xpath is None:
            raise ValueError(
                f"'{input_file}' uses index-based locations and requires "
                "--xpath=<section> to resolve indexes against the live "
                "pointer table."
            )
        indexed_strings = get_new_strings_indexed(input_file)
        logger.info(
            "Found %d translations to write (index-based)", len(indexed_strings)
        )
        if not indexed_strings:
            logger.info("No translations to write, skipping binary modification")
            return None
    else:
        new_strings = get_new_strings_auto(input_file)
        logger.info("Found %d translations to write", len(new_strings))
        if not new_strings:
            logger.info("No translations to write, skipping binary modification")
            return None

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

    if xpath is not None:
        config = common.read_extraction_config(xpath, headers_path)
        if fmt == "index":
            new_strings = resolve_indexes_to_offsets(
                indexed_strings, file_data, config
            )
        rebuild_section(file_data, config, new_strings, output_path)
        logger.info("Rebuilt section '%s' in %s", xpath, output_path)
    else:
        # Legacy append strategy (backward compatible).
        # Expand <join at="N"> tags so each sub-pointer is updated
        # independently — otherwise grouped sections like inf/quests
        # would write the literal join markup as a single string and
        # leave sibling pointers stale.
        expanded: list[tuple[int, str]] = []
        has_joins = False
        for offset, text in new_strings:
            pairs = parse_joined_text(offset, text)
            if len(pairs) > 1:
                has_joins = True
            expanded.extend(pairs)
        if has_joins:
            logger.warning(
                "CSV contains <join> tags (grouped pointer entries) but no "
                "--xpath was given. Falling back to append mode; prefer "
                "--xpath=<section> so rebuild_section is used and orphan "
                "pointers are avoided."
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

    :param input_file: Path to CSV file with translations
    :param output_file: Path to source FTXT binary file
    :param output_path: Path for the modified file. If None, auto-generated.
    :param compress: If True, compress output with JKR HFI
    :param encrypt: If True, encrypt output with ECD
    :param key_index: ECD key index (0-5, default 4)
    :return: Path to the modified file, or None if no changes
    """
    new_strings = get_new_strings_auto(input_file)
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

    :param input_file: Path to CSV file with translations
    :param output_file: Path to source scenario binary file
    :param output_path: Path for the modified file. If None, auto-generated.
    :param compress: If True, compress output with JKR HFI
    :param encrypt: If True, encrypt output with ECD
    :param key_index: ECD key index (0-5, default 4)
    :return: Path to the modified file, or None if no changes
    """
    new_strings = get_new_strings_auto(input_file)
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

    :param input_file: Path to CSV file with translations
    :param output_file: Path to source NPC dialogue binary file
    :param output_path: Path for the modified file. If None, auto-generated.
    :param compress: If True, compress output with JKR HFI
    :param encrypt: If True, encrypt output with ECD
    :param key_index: ECD key index (0-5, default 4)
    :return: Path to the modified file, or None if no changes
    """
    new_strings = get_new_strings_auto(input_file)
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
