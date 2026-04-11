"""
NPC dialogue text extraction for Monster Hunter Frontier.

Handles stage dialogue binary files with NPC table and per-NPC dialogue blocks.
"""
import struct

from .binary_file import BinaryFile
from .common import JOIN_MARKER, decode_game_string, load_file_data
from .pointer_tables import read_until_null

__all__ = [
    "extract_npc_dialogue",
    "extract_npc_dialogue_data",
]


def extract_npc_dialogue(file_path: str) -> list[dict[str, int | str]]:
    """
    Extract NPC dialogue text from a stage dialogue binary file.

    Binary format:
    - NPC table at offset 0: pairs of (npc_id: u32, pointer: u32)
      terminated by (0xFFFFFFFF, 0xFFFFFFFF)
    - Per-NPC dialogue block: header_size (u32) followed by
      relative pointers (u32 each), then null-terminated Shift-JIS strings

    :param file_path: Path to the dialogue file (auto-decrypts/decompresses)
    :return: List of dicts with "offset" and "text" keys
    """
    file_data = load_file_data(file_path)
    return extract_npc_dialogue_data(file_data)


def extract_npc_dialogue_data(data: bytes) -> list[dict[str, int | str]]:
    """
    Extract NPC dialogue text from raw bytes.

    :param data: Raw dialogue binary data
    :return: List of dicts with "offset" and "text" keys
    """
    if len(data) < 8:
        return []

    bfile = BinaryFile.from_bytes(data)

    # Read NPC table: (npc_id, pointer) pairs until 0xFFFFFFFF terminator
    npcs: list[tuple[int, int, int]] = []  # (npc_id, block_pointer, table_offset)
    pos = 0
    while pos + 8 <= len(data):
        bfile.seek(pos)
        npc_id = struct.unpack_from("<I", data, pos)[0]
        block_ptr = struct.unpack_from("<I", data, pos + 4)[0]
        if npc_id == 0xFFFFFFFF and block_ptr == 0xFFFFFFFF:
            break
        npcs.append((npc_id, block_ptr, pos))
        pos += 8

    if not npcs:
        return []

    results: list[dict[str, int | str | list[int]]] = []
    for npc_id, block_ptr, table_offset in npcs:
        if block_ptr + 4 > len(data):
            continue

        # Read header_size at the start of the NPC block
        header_size = struct.unpack_from("<I", data, block_ptr)[0]
        if header_size == 0:
            # No dialogues for this NPC
            results.append({
                "offset": table_offset,
                "text": "",
                "sub_offsets": [table_offset],
            })
            continue

        num_dialogues = header_size // 4
        pointers_start = block_ptr + 4  # skip header_size field

        # Read relative pointers, remembering the slot position of each
        # dialogue sub-pointer for downstream tools (even though the
        # standalone NPC-dialogue rebuild regenerates the binary from
        # scratch and doesn't use these offsets directly, keeping them
        # gives every grouped entry the same shape).
        dialogues: list[str] = []
        sub_offsets: list[int] = []
        for i in range(num_dialogues):
            ptr_pos = pointers_start + i * 4
            if ptr_pos + 4 > len(data):
                break
            rel_ptr = struct.unpack_from("<I", data, ptr_pos)[0]
            abs_ptr = block_ptr + rel_ptr
            if abs_ptr >= len(data):
                break
            bfile.seek(abs_ptr)
            raw = read_until_null(bfile)
            text = decode_game_string(raw, context=f"NPC {npc_id} dialogue {i}")
            dialogues.append(text)
            sub_offsets.append(ptr_pos)

        if not dialogues:
            results.append({
                "offset": table_offset,
                "text": "",
                "sub_offsets": [table_offset],
            })
            continue

        # Sub-strings live in one cell, separated by the clean ``{j}``
        # marker. The entry-level ``offset`` stays the NPC-table row,
        # which is what ``rebuild_npc_dialogue`` uses as a translation
        # key.
        results.append({
            "offset": table_offset,
            "text": JOIN_MARKER.join(dialogues),
            "sub_offsets": sub_offsets,
        })

    return results
