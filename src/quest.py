"""
Quest file text extraction for Monster Hunter Frontier.

Handles both standalone quest .bin files and quest text label definitions.
"""
import re
import struct

from .binary_file import BinaryFile, InvalidPointerError
from .common import decode_game_string, load_file_data
from .pointer_tables import read_until_null

__all__ = [
    "QUEST_TEXT_LABELS",
    "split_join_text",
    "extract_quest_file",
    "extract_quest_file_data",
]

# Quest text field names for labeled CSV export
QUEST_TEXT_LABELS = [
    "title", "textMain", "textSubA", "textSubB",
    "successCond", "failCond", "contractor", "description"
]


def split_join_text(text: str) -> list[str]:
    """
    Split a text with ``<join at="...">`` tags into individual strings.

    :param text: Text that may contain ``<join at="NNN">`` tags
    :return: List of individual strings
    """
    parts = re.split(r'<join at="[^"]*">', text)
    return parts


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
    try:
        bfile.validate_offset(
            quest_type_flags_offset + 3,
            context="questTypeFlagsPtr location"
        )
    except InvalidPointerError:
        raise ValueError(
            f"File too small ({len(data)} bytes) to be a quest file. "
            "Quest files need at least a header with questTypeFlagsPtr."
        )
    bfile.seek(quest_type_flags_offset)
    quest_type_flags_ptr = bfile.read_int()

    if quest_type_flags_ptr == 0:
        return []

    # Read QuestStringsPtr from main quest properties
    strings_ptr_addr = quest_type_flags_ptr + quest_strings_offset
    try:
        bfile.validate_offset(
            strings_ptr_addr + 3,
            context="QuestStringsPtr location"
        )
    except InvalidPointerError:
        raise ValueError(
            f"Not a valid quest file: questTypeFlagsPtr (0x{quest_type_flags_ptr:x}) "
            f"points outside the file ({len(data)} bytes). "
            "Make sure this is a quest .bin file, not a different game data file."
        )
    bfile.seek(strings_ptr_addr)
    quest_strings_ptr = bfile.read_int()

    if quest_strings_ptr == 0:
        return []

    # Read the text pointer block
    text_block_end = quest_strings_ptr + text_pointers_count * 4 - 1
    try:
        bfile.validate_offset(
            text_block_end,
            context=f"QuestText block at 0x{quest_strings_ptr:x}"
        )
    except InvalidPointerError:
        raise ValueError(
            f"Not a valid quest file: QuestStringsPtr (0x{quest_strings_ptr:x}) "
            f"points outside the file ({len(data)} bytes). "
            "Make sure this is a quest .bin file, not a different game data file."
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
