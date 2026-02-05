"""
Core module functions.
"""
import codecs
import json
import logging
import struct
import warnings
from typing import Iterator, Optional

from .binary_file import BinaryFile, InvalidPointerError
from .jkr_decompress import is_jkr_file, decompress_jkr, JKRError

logger = logging.getLogger(__name__)

# Escape sequence replacements for ReFrontier format compatibility.
# Format: (standard_string, refrontier_escape)
REFRONTIER_REPLACEMENTS: tuple[tuple[str, str], ...] = (
    ("\t", "<TAB>"),
    ("\r\n", "<CLINE>"),
    ("\n", "<NLINE>"),
)

# Encoding used by Monster Hunter Frontier
GAME_ENCODING = "shift_jisx0213"


class EncodingError(ValueError):
    """Raised when encoding or decoding fails for game text."""
    pass


def decode_game_string(
    data: bytes,
    errors: str = "replace",
    context: Optional[str] = None
) -> str:
    """
    Decode a byte string from the game's encoding (Shift-JIS).

    :param data: Raw bytes to decode
    :param errors: Error handling mode ('strict', 'replace', 'ignore')
    :param context: Optional context string for error messages (e.g., offset)
    :return: Decoded string
    :raises EncodingError: If errors='strict' and decoding fails
    """
    try:
        return codecs.decode(data, GAME_ENCODING, errors=errors)
    except (UnicodeDecodeError, LookupError) as exc:
        ctx = f" at {context}" if context else ""
        raise EncodingError(
            f"Failed to decode Shift-JIS string{ctx}: {exc}"
        ) from exc


def encode_game_string(
    text: str,
    errors: str = "strict",
    context: Optional[str] = None
) -> bytes:
    """
    Encode a string to the game's encoding (Shift-JIS).

    :param text: String to encode
    :param errors: Error handling mode ('strict', 'replace', 'ignore', 'xmlcharrefreplace')
    :param context: Optional context string for error messages
    :return: Encoded bytes
    :raises EncodingError: If errors='strict' and encoding fails
    """
    try:
        return codecs.encode(text, GAME_ENCODING, errors=errors)
    except (UnicodeEncodeError, LookupError) as exc:
        ctx = f" for {context}" if context else ""
        raise EncodingError(
            f"Failed to encode string to Shift-JIS{ctx}: {exc}. "
            f"String contains characters not representable in Shift-JIS."
        ) from exc


def skip_csv_header(reader: Iterator[list[str]], input_file: str) -> None:
    """
    Skip the header row of a CSV reader.

    :param reader: CSV reader object
    :param input_file: Input file path (for error messages)
    :raises InterruptedError: If the file has less than one line
    """
    try:
        next(reader)
    except StopIteration as exc:
        raise InterruptedError(f"{input_file} has less than one line!") from exc


DEFAULT_HEADERS_PATH = "headers.json"


def read_json_data(
    xpath: str = "dat/armor/head",
    headers_path: str = DEFAULT_HEADERS_PATH
) -> tuple[int, int, int]:
    """
    Read data from a JSON file.

    :param xpath: Data path as an XPATH.
        For instance, "dat/armor/head" to get 'headers.json'["dat"]["armors"]["head"].
    :param headers_path: Path to the headers.json configuration file.
    :return: Begin pointer, end pointer and crop before end
    """
    path = xpath.split("/")
    with open(headers_path, encoding="utf-8") as f:
        data = json.load(f)
        pointers = data
        for part in path:
            pointers = pointers[part]
        if "begin_pointer" not in pointers or "next_field_pointer" not in pointers:
            raise ValueError(
                "Please specify more precise path. Options are: '" +
                ",".join(pointers.keys()) + "'."
            )
        crop_end = 0
        if "crop_end" in pointers:
            crop_end = pointers["crop_end"]
        return (
            int(pointers["begin_pointer"], 16),
            int(pointers["next_field_pointer"], 16),
            crop_end,
        )


def read_until_null(bfile: BinaryFile) -> bytes:
    """
    Read data until we meet null terminator or end of file.

    :param bfile: File to read from
    :return: Data read as a binary stream
    """
    buffer = bytearray()
    byte = bfile.read(1)
    while byte != b"\x00" and byte != b"":
        buffer.extend(byte)
        byte = bfile.read(1)
    return bytes(buffer)


def read_next_string(bfile: BinaryFile) -> str:
    """
    Read a string from a position.

    :param bfile: Binary file positioned at a pointer
    :return: Decoded string
    :raises InvalidPointerError: If the pointer points outside the file
    """
    pointer = bfile.read_int()
    bfile.validate_offset(pointer, context="string pointer")
    bfile.seek(pointer)
    data_stream = read_until_null(bfile)
    return decode_game_string(data_stream, context=f"pointer 0x{pointer:x}")


def read_file_section(
    bfile: BinaryFile,
    start_position: int,
    length: int
) -> list[dict[str, int | str]]:
    """
    Read a part of a file and return strings found.

    :param bfile: Binary file to read from
    :param start_position: Initial position to read from
    :param length: Number of bytes to read.
    :return: List of dicts with "offset" and "text" keys
    :raises InvalidPointerError: If any pointer points outside the file
    """
    bfile.validate_offset(start_position, context="section start")
    if length > 0:
        bfile.validate_offset(start_position + length - 1, context="section end")

    bfile.seek(start_position)
    pointers_stream = bfile.read(length)
    # Get the list of continuous pointers
    pointers = struct.unpack(f"<{length // 4}I", pointers_stream)
    strings: list[str] = []
    ids: list[int] = []
    current_id = 0
    join_lines = 0 in pointers
    for pointer in pointers:
        # Frontier separates some multiline strings (e.g. weapon descriptions)
        # with multiple \x00 paddings
        if join_lines:
            if pointer == 0:
                current_id += 1
                continue
        else:
            current_id += 1
        # Validate pointer is within file bounds before seeking
        bfile.validate_offset(pointer, context=f"string at offset 0x{pointer:x}")
        # Move to string pointer
        bfile.seek(pointer)
        data_stream = read_until_null(bfile)
        strings.append(decode_game_string(data_stream, context=f"pointer 0x{pointer:x}"))
        ids.append(current_id)

    # Group output by id
    output: list[dict[str, int | str]] = []
    last_id = -1
    for offset, string, current_id in zip(
        range(start_position, start_position + length, 4),
        strings,
        ids
    ):
        if current_id == last_id:
            output[-1]["text"] += f'<join at="{offset}">{string}'
        else:
            output.append({"offset": offset, "text": string})
            last_id = current_id
    return output


def read_from_pointers(
    file_path: str,
    pointers_data: tuple[int, int, int]
) -> list[dict[str, int | str]]:
    """
    Read data using pointer headers.

    Automatically decompresses JPK files. ECD encrypted files must still
    be decrypted using ReFrontier first.

    :param file_path: Input file path
    :param pointers_data: Pointers indicated where to read.
    :return: List of dicts with "offset" and "text" keys
    """
    start_pointer = pointers_data[0]
    next_field_pointer = pointers_data[1]
    crop_end = pointers_data[2]

    # Read file and check headers
    with open(file_path, "rb") as f:
        file_data = f.read()

    # Check for encrypted file (must be handled externally)
    if file_data[:3] == b"ecd":
        warnings.warn(
            f"'{file_path}' starts with an ECD header, meaning it's encrypted. "
            + "Make sure to decrypt the file using ReFrontier before using it."
        )

    # Auto-decompress JPK files
    if is_jkr_file(file_data):
        try:
            file_data = decompress_jkr(file_data)
        except JKRError as exc:
            raise JKRError(f"Failed to decompress '{file_path}': {exc}") from exc

    # Use BinaryFile to work with the (potentially decompressed) data
    bfile = BinaryFile.from_bytes(file_data)

    # Move the file pointer to the desired start position
    bfile.seek(start_pointer)
    start_position = bfile.read_int()
    bfile.seek(next_field_pointer)
    read_length = bfile.read_int() - start_position - crop_end
    reads = read_file_section(bfile, start_position, read_length)

    return reads
