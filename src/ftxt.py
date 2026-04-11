"""
FTXT file format parsing for Monster Hunter Frontier.

FTXT files are standalone text files containing sequential null-terminated
Shift-JIS strings with a 16-byte header.
"""
import struct

from .binary_file import BinaryFile
from .common import decode_game_string, load_file_data
from .pointer_tables import read_until_null

__all__ = [
    "FTXT_MAGIC",
    "FTXT_HEADER_SIZE",
    "is_ftxt_file",
    "extract_ftxt",
    "extract_ftxt_data",
]

# FTXT file magic number
FTXT_MAGIC = 0x000B0000
FTXT_HEADER_SIZE = 16


def is_ftxt_file(data: bytes) -> bool:
    """
    Check if data is an FTXT text file.

    :param data: Raw file data (at least 4 bytes)
    :return: True if the data starts with FTXT magic (0x000B0000)
    """
    if len(data) < 4:
        return False
    magic = struct.unpack_from("<I", data, 0)[0]
    return magic == FTXT_MAGIC


def extract_ftxt(file_path: str) -> list[dict[str, int | str]]:
    """
    Extract text from an FTXT standalone text file.

    FTXT format (16-byte header):
    - 0x00: magic (u32) = 0x000B0000
    - 0x04: padding (6 bytes)
    - 0x0A: string_count (u16)
    - 0x0C: text_block_size (u32)
    - 0x10: null-terminated Shift-JIS strings

    :param file_path: Path to the FTXT file (auto-decrypts/decompresses)
    :return: List of dicts with "offset" and "text" keys
    """
    file_data = load_file_data(file_path)

    if not is_ftxt_file(file_data):
        raise ValueError(
            f"'{file_path}' is not an FTXT file "
            f"(expected magic 0x{FTXT_MAGIC:08X})"
        )

    if len(file_data) < FTXT_HEADER_SIZE:
        raise ValueError(
            f"FTXT file too small: {len(file_data)} bytes "
            f"(minimum {FTXT_HEADER_SIZE})"
        )

    string_count = struct.unpack_from("<H", file_data, 0x0A)[0]
    # text_block_size at 0x0C is informational; we parse by null terminators

    bfile = BinaryFile.from_bytes(file_data)
    bfile.seek(FTXT_HEADER_SIZE)

    results: list[dict[str, int | str | list[int]]] = []
    for _ in range(string_count):
        offset = bfile.tell()
        data_stream = read_until_null(bfile)
        text = decode_game_string(data_stream, context=f"FTXT offset 0x{offset:x}")
        results.append({
            "offset": offset,
            "text": text,
            "sub_offsets": [offset],
        })

    return results


def extract_ftxt_data(data: bytes) -> list[dict[str, int | str | list[int]]]:
    """
    Extract text from raw FTXT bytes (already loaded/decrypted/decompressed).

    :param data: Raw FTXT file data
    :return: List of dicts with "offset" and "text" keys
    """
    if not is_ftxt_file(data):
        raise ValueError(
            f"Data is not FTXT (expected magic 0x{FTXT_MAGIC:08X})"
        )

    if len(data) < FTXT_HEADER_SIZE:
        raise ValueError(
            f"FTXT data too small: {len(data)} bytes "
            f"(minimum {FTXT_HEADER_SIZE})"
        )

    string_count = struct.unpack_from("<H", data, 0x0A)[0]
    bfile = BinaryFile.from_bytes(data)
    bfile.seek(FTXT_HEADER_SIZE)

    results: list[dict[str, int | str | list[int]]] = []
    for _ in range(string_count):
        offset = bfile.tell()
        data_stream = read_until_null(bfile)
        text = decode_game_string(data_stream, context=f"FTXT offset 0x{offset:x}")
        results.append({
            "offset": offset,
            "text": text,
            "sub_offsets": [offset],
        })

    return results
