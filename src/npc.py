"""
NPC dialogue text extraction for Monster Hunter Frontier.

Handles stage dialogue binary files with NPC table and per-NPC dialogue blocks.
"""
import logging
import struct

from .binary_file import BinaryFile
from .common import JOIN_MARKER, decode_game_string, load_file_data
from .pointer_tables import read_until_null

__all__ = [
    "extract_npc_dialogue",
    "extract_npc_dialogue_data",
]

logger = logging.getLogger(__name__)

# Sanity caps used to reject obviously-invalid inputs (e.g. running
# ``--npc`` on a stage geometry ``.pac`` instead of a stage dialogue
# file). The format has no magic bytes, so without these the parser
# happily reinterprets random binary as ``(npc_id, pointer)`` pairs and
# produces multi-hundred-kilobyte garbage rows. Real stages have at
# most a handful of dozen NPCs and a couple of dozen dialogue lines
# each — these caps are several orders of magnitude beyond that.
_MAX_NPC_TABLE_ENTRIES = 10000
_MAX_DIALOGUES_PER_NPC = 1024
_MAX_HEADER_SIZE_BYTES = _MAX_DIALOGUES_PER_NPC * 4


def extract_npc_dialogue(file_path: str) -> list[dict[str, int | str]]:
    """
    Extract NPC dialogue text from a stage dialogue binary file.

    Binary format:
    - NPC table at offset 0: pairs of (npc_id: u32, pointer: u32)
      terminated by (0xFFFFFFFF, 0xFFFFFFFF)
    - Per-NPC dialogue block: header_size (u32), the offset of the first
      string from the block start, so the block holds header_size / 4
      strings; then one relative pointer (u32) per string after the
      first; then the null-terminated Shift-JIS strings

    :param file_path: Path to the dialogue file (auto-decrypts/decompresses)
    :return: List of dicts with "offset" and "text" keys
    :raises ValueError: If *data* doesn't look like an NPC dialogue file
    """
    file_data = load_file_data(file_path)
    return extract_npc_dialogue_data(file_data)


def extract_npc_dialogue_data(data: bytes) -> list[dict[str, int | str]]:
    """
    Extract NPC dialogue text from raw bytes.

    :param data: Raw dialogue binary data
    :return: List of dicts with "offset" and "text" keys
    :raises ValueError: If *data* doesn't look like an NPC dialogue file —
        the format has no magic bytes, so the parser validates the table
        and per-block structure and refuses to walk into garbage.
    """
    if len(data) < 8:
        return []

    bfile = BinaryFile.from_bytes(data)

    # Walk the NPC table: (npc_id, pointer) pairs until the
    # (0xFFFFFFFF, 0xFFFFFFFF) terminator. Cap the iteration count and
    # validate each block_ptr is within file bounds — running ``--npc``
    # on the wrong file type produces millions of plausible-looking
    # pairs, and without these checks the parser would happily process
    # them and emit garbage rows.
    npcs: list[tuple[int, int, int]] = []  # (npc_id, block_pointer, table_offset)
    pos = 0
    terminated = False
    while pos + 8 <= len(data):
        if len(npcs) >= _MAX_NPC_TABLE_ENTRIES:
            raise ValueError(
                f"NPC table did not terminate within "
                f"{_MAX_NPC_TABLE_ENTRIES} entries — input is likely "
                "not an NPC dialogue file."
            )
        bfile.seek(pos)
        npc_id = struct.unpack_from("<I", data, pos)[0]
        block_ptr = struct.unpack_from("<I", data, pos + 4)[0]
        if npc_id == 0xFFFFFFFF and block_ptr == 0xFFFFFFFF:
            terminated = True
            break
        if block_ptr + 4 > len(data):
            raise ValueError(
                f"NPC table entry {len(npcs)} at offset {pos:#x} has "
                f"block_ptr={block_ptr:#x} past end of file "
                f"({len(data):#x} bytes) — input is likely not an NPC "
                "dialogue file."
            )
        npcs.append((npc_id, block_ptr, pos))
        pos += 8

    if not terminated:
        raise ValueError(
            "NPC table terminator (0xFFFFFFFF, 0xFFFFFFFF) not found — "
            "input is likely not an NPC dialogue file."
        )

    if not npcs:
        return []

    results: list[dict[str, int | str | list[int]]] = []
    for npc_id, block_ptr, table_offset in npcs:
        # Read header_size at the start of the NPC block.
        # Validate it before trusting it as a length: ``--npc`` on a
        # stage geometry file gives header_size values in the billions
        # which would then drive ``num_dialogues`` into 8-figure
        # territory and read megabytes of binary as text.
        header_size = struct.unpack_from("<I", data, block_ptr)[0]
        if header_size > _MAX_HEADER_SIZE_BYTES or header_size % 4 != 0:
            raise ValueError(
                f"NPC {npc_id:#x} block at {block_ptr:#x} has implausible "
                f"header_size={header_size} (cap "
                f"{_MAX_HEADER_SIZE_BYTES}, must be multiple of 4) — "
                "input is likely not an NPC dialogue file."
            )
        if header_size == 0:
            # No dialogues for this NPC
            results.append({
                "offset": table_offset,
                "text": "",
                "sub_offsets": [table_offset],
            })
            continue

        # header_size is the offset of the first string from the block
        # start (it counts its own field): the first string has no
        # pointer, and the header_size / 4 - 1 pointers after the field
        # give the offsets of the others.
        num_dialogues = header_size // 4
        if block_ptr + header_size > len(data):
            raise ValueError(
                f"NPC {npc_id:#x} block at {block_ptr:#x} declares "
                f"{num_dialogues} strings but its header runs past the "
                "end of the file — input is likely not an NPC dialogue file."
            )
        string_ptrs = [(block_ptr + header_size, block_ptr)]
        for i in range(1, num_dialogues):
            ptr_pos = block_ptr + 4 * i
            rel_ptr = struct.unpack_from("<I", data, ptr_pos)[0]
            string_ptrs.append((block_ptr + rel_ptr, ptr_pos))

        # Each dialogue's sub_offset is its pointer slot (the header_size
        # field for the first one). The standalone rebuild regenerates the
        # blocks, so it does not use them, but every grouped entry keeps
        # the same shape.
        dialogues: list[str] = []
        sub_offsets: list[int] = []
        for i, (abs_ptr, slot) in enumerate(string_ptrs):
            if abs_ptr >= len(data):
                raise ValueError(
                    f"NPC {npc_id:#x} dialogue {i} points to {abs_ptr:#x}, "
                    f"past the end of the file ({len(data):#x} bytes) — "
                    "input is likely not an NPC dialogue file."
                )
            bfile.seek(abs_ptr)
            raw = read_until_null(bfile)
            text = decode_game_string(raw, context=f"NPC {npc_id} dialogue {i}")
            dialogues.append(text)
            sub_offsets.append(slot)

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
