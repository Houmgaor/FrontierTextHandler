"""
FTXT file format parsing for Monster Hunter Frontier.

An FTXT file starts with a text block of sequential null-terminated
Shift-JIS strings; other data may follow it (the entries of
dat/extend/mazpac.bin carry about 900 KB after their 156 strings).

Header (20 bytes):
    0x00  u32  magic 0x000B0000
    0x04  u32  total size of the file
    0x08  u32  0
    0x0C  u16  1 (unknown)
    0x0E  u16  string count
    0x10  u32  text block size
    0x14       text block: the strings, then a short tail up to the block
               size (in mazpac, 0xFF padding to a 4-byte boundary, then
               8 bytes)

ReFrontier's first FTXT reader (2019) skipped 10 bytes from after the
magic, so it read the count at 0x0E. A 2026 refactor made that seek
absolute (0x0A), and the ImHex pattern and FTH copied the 0x0A layout,
which reads a count of 0 from real files.
"""
import struct

from .binary_file import BinaryFile
from .common import decode_game_string, load_file_data
from .pointer_tables import read_until_null

__all__ = [
    "FTXT_MAGIC",
    "FTXT_HEADER_SIZE",
    "FTXT_SIZE_OFFSET",
    "FTXT_COUNT_OFFSET",
    "FTXT_BLOCK_SIZE_OFFSET",
    "is_ftxt_file",
    "extract_ftxt",
    "extract_ftxt_data",
    "repad_ftxt_tail",
]

# FTXT file magic number
FTXT_MAGIC = 0x000B0000
FTXT_SIZE_OFFSET = 0x04
FTXT_COUNT_OFFSET = 0x0E
FTXT_BLOCK_SIZE_OFFSET = 0x10
FTXT_HEADER_SIZE = 0x14


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

    :param file_path: Path to the FTXT file (auto-decrypts/decompresses)
    :return: List of dicts with "offset" and "text" keys
    """
    return extract_ftxt_data(load_file_data(file_path))


def extract_ftxt_data(data: bytes) -> list[dict[str, int | str | list[int]]]:
    """
    Extract text from raw FTXT bytes (already loaded/decrypted/decompressed).

    Reads the header's string count of strings from the start of the text
    block (see the module docstring for the layout).

    :param data: Raw FTXT file data
    :return: List of dicts with "offset" and "text" keys
    :raises ValueError: If *data* is not FTXT, or its strings run past
        the text block
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

    string_count = struct.unpack_from("<H", data, FTXT_COUNT_OFFSET)[0]
    block_size = struct.unpack_from("<I", data, FTXT_BLOCK_SIZE_OFFSET)[0]
    block_end = FTXT_HEADER_SIZE + block_size
    bfile = BinaryFile.from_bytes(data)
    bfile.seek(FTXT_HEADER_SIZE)

    results: list[dict[str, int | str | list[int]]] = []
    for _ in range(string_count):
        offset = bfile.tell()
        data_stream = read_until_null(bfile)
        if bfile.tell() > block_end:
            raise ValueError(
                f"FTXT string {len(results)} at 0x{offset:x} runs past the "
                f"text block (ends at 0x{block_end:x}); the header does "
                "not describe a text block."
            )
        text = decode_game_string(data_stream, context=f"FTXT offset 0x{offset:x}")
        results.append({
            "offset": offset,
            "text": text,
            "sub_offsets": [offset],
        })

    return results


def repad_ftxt_tail(tail: bytes, old_strings_end: int, new_strings_end: int) -> bytes:
    """
    Re-pad the tail of a text block for strings that now end elsewhere.

    In mazpac.bin the tail is 0xFF padding up to a 4-byte boundary (1 to 3
    bytes in the files seen), then 8 bytes. The padding is rewritten for
    the new end of the strings, with at least one 0xFF: strings that end
    on a boundary get four. A tail that doesn't follow this layout is
    kept as it is.

    :param tail: Bytes between the end of the original strings and the end
        of the text block
    :param old_strings_end: File offset where the original strings ended
    :param new_strings_end: File offset where the new strings end
    :return: The tail to write after the new strings
    """
    rest = tail.lstrip(b"\xff")
    padding = len(tail) - len(rest)
    if padding == 0 or (old_strings_end + padding) % 4:
        return tail
    return b"\xff" * (4 - new_strings_end % 4) + rest
