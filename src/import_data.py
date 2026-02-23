"""
Import data from a CSV file to a binary file.
"""
import csv
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
    new_strings = get_new_strings(input_file)
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

    if is_encrypted_file(file_data):
        file_data, _ = decrypt(file_data)
        logger.info("Auto-decrypted source file")

    if is_jkr_file(file_data):
        file_data = decompress_jkr(file_data)
        logger.info("Auto-decompressed source file")

    if xpath is not None:
        config = common.read_extraction_config(xpath, headers_path)
        rebuild_section(file_data, config, new_strings, output_path)
        logger.info("Rebuilt section '%s' in %s", xpath, output_path)
    else:
        # Legacy append strategy (backward compatible)
        pointers_to_update = [offset for offset, _ in new_strings]
        with open(output_path, "wb") as f:
            f.write(file_data)
        append_to_binary(new_strings, tuple(pointers_to_update), output_path)
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
    new_strings = get_new_strings(input_file)
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
