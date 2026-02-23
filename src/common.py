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
from .crypto import is_encrypted_file, decrypt, CryptoError

logger = logging.getLogger(__name__)

# FTXT file magic number
FTXT_MAGIC = 0x000B0000
FTXT_HEADER_SIZE = 16

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


def _is_extraction_leaf(value: dict) -> bool:
    """
    Check if a headers.json node is a leaf extraction config.

    Leaf nodes must have ``begin_pointer`` plus one of these mode indicators:

    - Standard pointer-pair: ``next_field_pointer``
    - Count-based pointer table: ``count_pointer``
    - Struct-strided fields: ``entry_count`` + ``entry_size`` + ``field_offset``
    - Indirect count (flat or strided): ``count_base_pointer`` + ``count_offset``
    - Null-terminated: ``null_terminated``
    - Null-terminated grouped: ``null_terminated`` + ``grouped_entries``
    - Quest table: ``quest_table``
    """
    if "begin_pointer" not in value:
        return False
    return (
        "next_field_pointer" in value
        or "count_pointer" in value
        or "entry_count" in value
        or "count_base_pointer" in value
        or value.get("null_terminated") is True
        or value.get("quest_table") is True
    )


def get_all_xpaths(headers_path: str = DEFAULT_HEADERS_PATH) -> list[str]:
    """
    Get all valid xpaths from the headers configuration.

    Recursively traverses the headers.json structure to find all
    leaf nodes with extraction configurations.

    :param headers_path: Path to the headers.json configuration file.
    :return: List of xpath strings (e.g., ["dat/armors/head", "dat/weapons/melee/name"])
    """
    with open(headers_path, encoding="utf-8") as f:
        data = json.load(f)

    xpaths = []

    def traverse(obj: dict, path: list[str]) -> None:
        """Recursively traverse to find leaf nodes with pointer data."""
        for key, value in obj.items():
            # Skip comment fields
            if key.startswith("_"):
                continue
            if not isinstance(value, dict):
                continue
            # Check if this is a leaf node with extraction config
            if _is_extraction_leaf(value):
                xpaths.append("/".join(path + [key]))
            else:
                # Recurse into nested structure
                traverse(value, path + [key])

    traverse(data, [])
    return sorted(xpaths)


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

    # Auto-decrypt ECD/EXF files
    if is_encrypted_file(file_data):
        try:
            file_data, _ = decrypt(file_data)
        except CryptoError as exc:
            raise CryptoError(f"Failed to decrypt '{file_path}': {exc}") from exc

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


def load_file_data(file_path: str) -> bytes:
    """
    Load a game file, auto-decrypting and decompressing as needed.

    :param file_path: Path to the game file
    :return: Raw binary data ready for parsing
    """
    with open(file_path, "rb") as f:
        file_data = f.read()

    if is_encrypted_file(file_data):
        try:
            file_data, _ = decrypt(file_data)
        except CryptoError as exc:
            raise CryptoError(f"Failed to decrypt '{file_path}': {exc}") from exc

    if is_jkr_file(file_data):
        try:
            file_data = decompress_jkr(file_data)
        except JKRError as exc:
            raise JKRError(f"Failed to decompress '{file_path}': {exc}") from exc

    return file_data


def read_extraction_config(
    xpath: str,
    headers_path: str = DEFAULT_HEADERS_PATH
) -> dict:
    """
    Read the extraction configuration for a given xpath.

    Returns the raw dict from headers.json for the given xpath leaf node.

    :param xpath: Data path (e.g., "jmp/menu/title")
    :param headers_path: Path to the headers.json configuration file
    :return: Config dict with extraction parameters
    :raises ValueError: If the xpath doesn't point to a valid leaf node
    :raises KeyError: If the xpath path doesn't exist
    """
    path = xpath.split("/")
    with open(headers_path, encoding="utf-8") as f:
        data = json.load(f)
    node = data
    for part in path:
        node = node[part]
    if not isinstance(node, dict) or not _is_extraction_leaf(node):
        raise ValueError(
            "Please specify more precise path. Options are: '"
            + ",".join(k for k in node.keys() if not k.startswith("_")) + "'."
        )
    return node


def read_multi_pointer_entries(
    bfile: BinaryFile,
    start_position: int,
    pointers_per_entry: int
) -> list[dict[str, int | str]]:
    """
    Read null-terminated multi-pointer entries with correct grouping.

    Each entry has a fixed number of string pointers.  Null internal
    pointers are skipped (they don't carry a string), and the terminator
    is an entry whose **first** pointer is 0.  Strings within the same
    entry are joined with ``<join>`` tags.

    This avoids the bug in :func:`read_file_section` where null internal
    pointers would incorrectly split/merge entry boundaries.

    :param bfile: Binary file to read from
    :param start_position: File offset of the first entry
    :param pointers_per_entry: Number of u32 pointers per entry
    :return: List of dicts with "offset" and "text" keys
    """
    results: list[dict[str, int | str]] = []
    pos = start_position

    while True:
        bfile.validate_offset(pos, context="multi-pointer entry scan")
        bfile.seek(pos)
        first_ptr = bfile.read_int()
        if first_ptr == 0:
            break

        # Read all pointers for this entry
        bfile.seek(pos)
        raw = bfile.read(pointers_per_entry * 4)
        ptrs = struct.unpack(f"<{pointers_per_entry}I", raw)

        entry: dict[str, int | str] | None = None
        for i, ptr in enumerate(ptrs):
            if ptr == 0:
                continue
            bfile.validate_offset(ptr, context=f"string pointer in entry at 0x{pos:x}")
            bfile.seek(ptr)
            data_stream = read_until_null(bfile)
            text = decode_game_string(data_stream, context=f"pointer 0x{ptr:x}")
            ptr_offset = pos + i * 4
            if entry is None:
                entry = {"offset": ptr_offset, "text": text}
            else:
                entry["text"] += f'<join at="{ptr_offset}">{text}'

        if entry is not None:
            results.append(entry)

        pos += pointers_per_entry * 4

    return results


def read_struct_strings(
    bfile: BinaryFile,
    base_offset: int,
    entry_count: int,
    entry_size: int,
    field_offset: int
) -> list[dict[str, int | str]]:
    """
    Read strings from struct fields at regular intervals.

    Extracts string pointers embedded in repeated structs (e.g., menu
    entries where title/description pointers sit at a fixed offset
    within each struct).

    :param bfile: Binary file to read from
    :param base_offset: Start address of the struct array in the file
    :param entry_count: Number of structs in the array
    :param entry_size: Size of each struct in bytes
    :param field_offset: Byte offset of the string pointer within each struct
    :return: List of dicts with "offset" and "text" keys
    """
    results: list[dict[str, int | str]] = []
    for i in range(entry_count):
        pointer_offset = base_offset + i * entry_size + field_offset
        bfile.validate_offset(
            pointer_offset,
            context=f"struct entry {i} field at +0x{field_offset:x}"
        )
        bfile.seek(pointer_offset)
        pointer = bfile.read_int()
        if pointer == 0:
            continue
        bfile.validate_offset(pointer, context=f"string pointer in entry {i}")
        bfile.seek(pointer)
        data_stream = read_until_null(bfile)
        text = decode_game_string(data_stream, context=f"struct entry {i}")
        results.append({"offset": pointer_offset, "text": text})
    return results


def _read_indirect_count(bfile: BinaryFile, config: dict) -> int:
    """
    Read an entry count from an indirect pointer table.

    Dereferences a base pointer in the file header, then reads a u16 or u32
    count at a fixed offset within that table.

    :param bfile: Binary file to read from
    :param config: Extraction config containing count_base_pointer,
        count_offset, count_type, and optional count_adjust
    :return: The count value (with adjustment applied)
    """
    count_base_pointer = int(config["count_base_pointer"], 16)
    count_offset = int(config["count_offset"], 16)
    count_type = config.get("count_type", "u16")
    count_adjust = config.get("count_adjust", 0)

    bfile.seek(count_base_pointer)
    base_addr = bfile.read_int()
    count_addr = base_addr + count_offset
    bfile.validate_offset(count_addr, context="indirect count address")
    bfile.seek(count_addr)
    if count_type == "u16":
        count = struct.unpack_from("<H", bfile.read(2))[0]
    else:
        count = struct.unpack_from("<I", bfile.read(4))[0]
    return count + count_adjust


def read_quest_table(
    bfile: BinaryFile,
    category_table_ptr: int,
    num_categories: int,
    quest_text_offset: int = 0x28,
    text_pointers_count: int = 8
) -> list[dict[str, int | str]]:
    """
    Read quest text from a multi-level category table (mhfinf.bin).

    Walks the category table, follows quest pointers, and reads string
    sub-pointers from each quest's text block.

    :param bfile: Binary file to read from
    :param category_table_ptr: File offset of the category table
    :param num_categories: Number of category entries
    :param quest_text_offset: Byte offset of text pointer within QUEST_INFO_TBL
    :param text_pointers_count: Number of string pointers per quest text block
    :return: List of dicts with "offset" and "text" keys
    """
    results: list[dict[str, int | str]] = []

    for cat_idx in range(num_categories):
        cat_addr = category_table_ptr + cat_idx * 8
        bfile.validate_offset(cat_addr + 7, context=f"category {cat_idx}")
        bfile.seek(cat_addr + 2)  # skip endID u16
        count = struct.unpack_from("<H", bfile.read(2))[0]
        quest_array_ptr = bfile.read_int()

        if quest_array_ptr == 0 or count == 0:
            continue

        # Read all quest pointers for this category
        bfile.validate_offset(
            quest_array_ptr + count * 4 - 1,
            context=f"category {cat_idx} quest array"
        )
        bfile.seek(quest_array_ptr)
        quest_ptrs = struct.unpack(f"<{count}I", bfile.read(count * 4))

        for quest_ptr in quest_ptrs:
            if quest_ptr == 0:
                continue

            # Read text block pointer from QUEST_INFO_TBL + quest_text_offset
            text_ptr_addr = quest_ptr + quest_text_offset
            bfile.validate_offset(
                text_ptr_addr + 3,
                context=f"quest at 0x{quest_ptr:x} text field"
            )
            bfile.seek(text_ptr_addr)
            text_block_ptr = bfile.read_int()

            if text_block_ptr == 0:
                continue

            # Read string sub-pointers
            text_block_end = text_block_ptr + text_pointers_count * 4 - 1
            bfile.validate_offset(
                text_block_end,
                context=f"quest text block at 0x{text_block_ptr:x}"
            )
            bfile.seek(text_block_ptr)
            str_ptrs = struct.unpack(
                f"<{text_pointers_count}I",
                bfile.read(text_pointers_count * 4)
            )

            # Read strings and group with joins
            entry: dict[str, int | str] | None = None
            for i, sp in enumerate(str_ptrs):
                if sp == 0:
                    continue
                bfile.validate_offset(
                    sp, context=f"quest string ptr {i} at 0x{sp:x}"
                )
                bfile.seek(sp)
                data_stream = read_until_null(bfile)
                text = decode_game_string(
                    data_stream, context=f"quest string 0x{sp:x}"
                )
                ptr_offset = text_block_ptr + i * 4
                if entry is None:
                    entry = {"offset": ptr_offset, "text": text}
                else:
                    entry["text"] += f'<join at="{ptr_offset}">{text}'
            if entry is not None:
                results.append(entry)

    return results


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

    results: list[dict[str, int | str]] = []
    for _ in range(string_count):
        offset = bfile.tell()
        data_stream = read_until_null(bfile)
        text = decode_game_string(data_stream, context=f"FTXT offset 0x{offset:x}")
        results.append({"offset": offset, "text": text})

    return results


def extract_ftxt_data(data: bytes) -> list[dict[str, int | str]]:
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

    results: list[dict[str, int | str]] = []
    for _ in range(string_count):
        offset = bfile.tell()
        data_stream = read_until_null(bfile)
        text = decode_game_string(data_stream, context=f"FTXT offset 0x{offset:x}")
        results.append({"offset": offset, "text": text})

    return results


def extract_quest_file(
    file_path: str,
    quest_type_flags_offset: int = 0x00,
    quest_strings_offset: int = 0xE8,
    text_pointers_count: int = 8
) -> list[dict[str, int | str]]:
    """
    Extract text from a standalone quest .bin file.

    Quest file layout:
    - Header at 0x00 contains questTypeFlagsPtr (u32 at quest_type_flags_offset)
    - Main quest properties at questTypeFlagsPtr contain QuestStringsPtr
      (u32 at quest_strings_offset within the main quest props block)
    - QuestText block: 8 consecutive u32 pointers to null-terminated Shift-JIS strings
      (title, textMain, textSubA, textSubB, successCond, failCond, contractor, description)

    :param file_path: Path to the quest .bin file (auto-decrypts/decompresses)
    :param quest_type_flags_offset: Offset of questTypeFlagsPtr in the file header
    :param quest_strings_offset: Offset of QuestStringsPtr within main quest properties
    :param text_pointers_count: Number of string pointers in QuestText block (default 8)
    :return: List of dicts with "offset" and "text" keys
    """
    file_data = load_file_data(file_path)
    return extract_quest_file_data(
        file_data, quest_type_flags_offset,
        quest_strings_offset, text_pointers_count
    )


def extract_quest_file_data(
    data: bytes,
    quest_type_flags_offset: int = 0x00,
    quest_strings_offset: int = 0xE8,
    text_pointers_count: int = 8
) -> list[dict[str, int | str]]:
    """
    Extract text from raw quest file bytes.

    :param data: Raw quest file data
    :param quest_type_flags_offset: Offset of questTypeFlagsPtr in the file header
    :param quest_strings_offset: Offset of QuestStringsPtr within main quest properties
    :param text_pointers_count: Number of string pointers in QuestText block (default 8)
    :return: List of dicts with "offset" and "text" keys
    """
    bfile = BinaryFile.from_bytes(data)

    # Read questTypeFlagsPtr from the file header
    bfile.validate_offset(
        quest_type_flags_offset + 3,
        context="questTypeFlagsPtr location"
    )
    bfile.seek(quest_type_flags_offset)
    quest_type_flags_ptr = bfile.read_int()

    if quest_type_flags_ptr == 0:
        return []

    # Read QuestStringsPtr from main quest properties
    strings_ptr_addr = quest_type_flags_ptr + quest_strings_offset
    bfile.validate_offset(
        strings_ptr_addr + 3,
        context="QuestStringsPtr location"
    )
    bfile.seek(strings_ptr_addr)
    quest_strings_ptr = bfile.read_int()

    if quest_strings_ptr == 0:
        return []

    # Read the text pointer block
    text_block_end = quest_strings_ptr + text_pointers_count * 4 - 1
    bfile.validate_offset(
        text_block_end,
        context=f"QuestText block at 0x{quest_strings_ptr:x}"
    )
    bfile.seek(quest_strings_ptr)
    str_ptrs = struct.unpack(
        f"<{text_pointers_count}I",
        bfile.read(text_pointers_count * 4)
    )

    # Read strings, grouping with <join> tags like quest table mode
    results: list[dict[str, int | str]] = []
    entry: dict[str, int | str] | None = None
    for i, sp in enumerate(str_ptrs):
        if sp == 0:
            continue
        bfile.validate_offset(sp, context=f"quest string ptr {i} at 0x{sp:x}")
        bfile.seek(sp)
        data_stream = read_until_null(bfile)
        text = decode_game_string(data_stream, context=f"quest string 0x{sp:x}")
        ptr_offset = quest_strings_ptr + i * 4
        if entry is None:
            entry = {"offset": ptr_offset, "text": text}
        else:
            entry["text"] += f'<join at="{ptr_offset}">{text}'
    if entry is not None:
        results.append(entry)

    return results


# Quest text field names for labeled CSV export
QUEST_TEXT_LABELS = [
    "title", "textMain", "textSubA", "textSubB",
    "successCond", "failCond", "contractor", "description"
]


def extract_text_data(
    file_path: str,
    config: dict
) -> list[dict[str, int | str]]:
    """
    Extract text from a game file based on extraction config.

    Supports these extraction modes:
    - Standard pointer-pair (begin_pointer + next_field_pointer)
    - Count-based pointer table (begin_pointer + count_pointer)
    - Indirect count flat (begin_pointer + count_base_pointer, no entry_size)
    - Indirect count strided (begin_pointer + count_base_pointer + entry_size)
    - Null-terminated (begin_pointer + null_terminated)
    - Struct-strided fields (begin_pointer + entry_count + entry_size)
    - Quest table (begin_pointer + quest_table)

    :param file_path: Path to the game file
    :param config: Extraction config dict from headers.json
    :return: List of dicts with "offset" and "text" keys
    """
    file_data = load_file_data(file_path)
    bfile = BinaryFile.from_bytes(file_data)

    begin_pointer = int(config["begin_pointer"], 16)

    if "next_field_pointer" in config:
        # Standard: pointer pair defining start and end of pointer table
        next_field_pointer = int(config["next_field_pointer"], 16)
        crop_end = config.get("crop_end", 0)

        bfile.seek(begin_pointer)
        start_position = bfile.read_int()
        bfile.seek(next_field_pointer)
        read_length = bfile.read_int() - start_position - crop_end
        return read_file_section(bfile, start_position, read_length)

    elif "count_pointer" in config:
        # Count-based: pointer to array start + pointer to entry count
        count_pointer = int(config["count_pointer"], 16)

        bfile.seek(begin_pointer)
        start_position = bfile.read_int()
        bfile.seek(count_pointer)
        count = bfile.read_int()
        if count == 0:
            return []
        read_length = count * 4
        return read_file_section(bfile, start_position, read_length)

    elif config.get("quest_table"):
        # Quest table: multi-level category table (mhfinf.bin)
        count = _read_indirect_count(bfile, config)
        if count == 0:
            return []

        bfile.seek(begin_pointer)
        category_table_ptr = bfile.read_int()
        quest_text_offset = int(config.get("quest_text_offset", "0x28"), 16)
        text_pointers_count = config.get("text_pointers_count", 8)
        return read_quest_table(
            bfile, category_table_ptr, count,
            quest_text_offset, text_pointers_count
        )

    elif "count_base_pointer" in config and "entry_size" in config:
        # Indirect count strided: count from indirect table, struct-strided read
        entry_size = config["entry_size"]
        field_offset = config["field_offset"]
        count = _read_indirect_count(bfile, config)
        if count == 0:
            return []

        bfile.seek(begin_pointer)
        base_offset = bfile.read_int()
        return read_struct_strings(
            bfile, base_offset, count, entry_size, field_offset
        )

    elif "count_base_pointer" in config:
        # Indirect count flat: count from indirect table, flat pointer array
        pointers_per_entry = config.get("pointers_per_entry", 1)
        count = _read_indirect_count(bfile, config)
        if count == 0:
            return []

        bfile.seek(begin_pointer)
        start_position = bfile.read_int()
        read_length = count * pointers_per_entry * 4
        return read_file_section(bfile, start_position, read_length)

    elif config.get("null_terminated"):
        # Null-terminated: scan pointer groups until first pointer of group is 0
        pointers_per_entry = config.get("pointers_per_entry", 1)
        group_bytes = pointers_per_entry * 4

        bfile.seek(begin_pointer)
        start_position = bfile.read_int()

        if config.get("grouped_entries") and pointers_per_entry > 1:
            # Grouped mode: read fixed-size entries with correct boundaries
            return read_multi_pointer_entries(
                bfile, start_position, pointers_per_entry
            )

        # Legacy mode: scan to find array length, use flat read_file_section
        pos = start_position
        while True:
            bfile.validate_offset(pos, context="null-terminated scan")
            bfile.seek(pos)
            first_ptr = bfile.read_int()
            if first_ptr == 0:
                break
            pos += group_bytes

        read_length = pos - start_position
        if read_length == 0:
            return []
        return read_file_section(bfile, start_position, read_length)

    elif "entry_count" in config:
        # Struct-strided: read string pointers at fixed intervals in struct array
        entry_count = config["entry_count"]
        entry_size = config["entry_size"]
        field_offset = config["field_offset"]

        bfile.seek(begin_pointer)
        base_offset = bfile.read_int()
        return read_struct_strings(
            bfile, base_offset, entry_count, entry_size, field_offset
        )

    else:
        raise ValueError(f"Unknown extraction config format: {list(config.keys())}")
