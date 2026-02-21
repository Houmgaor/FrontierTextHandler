"""
Import data from a CSV file to a binary file.
"""
import csv
import logging
import os
import shutil
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


DEFAULT_OUTPUT_DIR = "output"


def import_from_csv(
    input_file: str,
    output_file: str,
    output_path: Optional[str] = None,
    compress: bool = False,
    encrypt: bool = False,
    key_index: int = DEFAULT_KEY_INDEX
) -> Optional[str]:
    """
    Use the CSV file to edit the binary file.

    :param input_file: Path to CSV file with translations
    :param output_file: Path to source binary file
    :param output_path: Path for the modified binary file. If None, uses
        '{output_dir}/{basename}-modified.bin' where basename is derived from output_file.
    :param compress: If True, compress the output using JKR HFI compression
    :param encrypt: If True, encrypt the output using ECD encryption
    :param key_index: ECD key index to use (0-5). Default is 4.
    :return: Path to the modified binary file, or None if no changes
    """
    new_strings = get_new_strings(input_file)
    logger.info("Found %d translations to write", len(new_strings))

    if not new_strings:
        logger.info("No translations to write, skipping binary modification")
        return None

    pointers_to_update: list[int] = []

    with BinaryFile(output_file) as bfile:
        for candidate in new_strings:
            bfile.seek(candidate[0])
            pointers_to_update.append(candidate[0])

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

    with open(output_path, "wb") as f:
        f.write(file_data)

    append_to_binary(new_strings, tuple(pointers_to_update), output_path)
    logger.info("Wrote output to %s", output_path)

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
