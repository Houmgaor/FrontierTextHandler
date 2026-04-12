"""
Pointer table reading and text extraction from binary game files.
"""
import struct
from typing import Optional

from .binary_file import BinaryFile, InvalidPointerError
from .common import (
    JOIN_MARKER,
    decode_game_string,
    load_file_data,
    GAME_ENCODING,
)

DEFAULT_GAME_VERSION = "zz"

__all__ = [
    "DEFAULT_GAME_VERSION",
    "resolve_entry_count",
    "read_until_null",
    "read_next_string",
    "read_file_section",
    "read_from_pointers",
    "read_multi_pointer_entries",
    "read_struct_strings",
    "read_quest_table",
    "scan_region_for_strings",
    "extract_text_data",
    "extract_text_data_from_bytes",
]


def resolve_entry_count(
    entry_count_value: int | dict[str, int],
    game_version: str = DEFAULT_GAME_VERSION,
) -> int:
    """
    Resolve an ``entry_count`` field from headers.json.

    Accepts either a plain integer (version-independent) or a dict
    mapping game version keys to counts.

    :param entry_count_value: Scalar count or ``{"zz": N, "ko": M, …}`` map.
    :param game_version: Which game version to look up (default ``"zz"``).
    :return: The resolved integer count.
    :raises ValueError: If the version is missing from the map.
    :raises TypeError: If the value is neither int nor dict.
    """
    if isinstance(entry_count_value, int):
        return entry_count_value
    if isinstance(entry_count_value, dict):
        version = game_version.lower()
        if version in entry_count_value:
            return entry_count_value[version]
        raise ValueError(
            f"No entry_count for game version '{version}'. "
            f"Available: {sorted(entry_count_value.keys())}"
        )
    raise TypeError(
        f"entry_count must be int or dict, got {type(entry_count_value).__name__}"
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
) -> list[dict[str, int | str | list[int]]]:
    """
    Read a part of a file and return strings found.

    Grouped entries (sections where a logical string is spread across
    several consecutive pointer slots separated by null slots) are
    surfaced as a single row whose ``text`` contains ``{j}``-separated
    sub-strings and whose ``sub_offsets`` list carries the slot offset
    of each non-null sibling pointer. Non-grouped sections produce one
    row per non-null pointer with a single-element ``sub_offsets``.

    :param bfile: Binary file to read from
    :param start_position: Initial position to read from
    :param length: Number of bytes to read.
    :return: List of dicts with ``"offset"``, ``"text"``, and
        ``"sub_offsets"`` keys. ``"offset"`` is the first slot of the
        entry; ``"sub_offsets"`` is the full list.
    :raises InvalidPointerError: If any pointer points outside the file
    """
    bfile.validate_offset(start_position, context="section start")
    if length > 0:
        bfile.validate_offset(start_position + length - 1, context="section end")

    bfile.seek(start_position)
    pointers_stream = bfile.read(length)
    # Get the list of continuous pointers
    pointers = struct.unpack(f"<{length // 4}I", pointers_stream)
    # Frontier separates some multiline strings (e.g. weapon descriptions)
    # with null pointers acting as group boundaries. When any pointer in
    # the read window is null we switch to grouped mode; otherwise every
    # non-null pointer is its own entry.
    join_lines = 0 in pointers

    # Walk the pointer window once. For each non-null pointer read the
    # target string and remember the (real) slot offset, keeping groups
    # together across null separators.
    output: list[dict[str, int | str | list[int]]] = []
    current_texts: list[str] = []
    current_offsets: list[int] = []

    def _flush_group() -> None:
        if not current_texts:
            return
        output.append({
            "offset": current_offsets[0],
            "text": JOIN_MARKER.join(current_texts),
            "sub_offsets": list(current_offsets),
        })
        current_texts.clear()
        current_offsets.clear()

    for i, pointer in enumerate(pointers):
        slot_offset = start_position + i * 4
        if pointer == 0:
            if join_lines:
                # Null terminates the current group.
                _flush_group()
            continue
        bfile.validate_offset(
            pointer, context=f"string at offset 0x{pointer:x}"
        )
        bfile.seek(pointer)
        data_stream = read_until_null(bfile)
        text = decode_game_string(
            data_stream, context=f"pointer 0x{pointer:x}"
        )
        if join_lines:
            current_texts.append(text)
            current_offsets.append(slot_offset)
        else:
            output.append({
                "offset": slot_offset,
                "text": text,
                "sub_offsets": [slot_offset],
            })
    _flush_group()
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
    from .jkr_decompress import is_jkr_file, decompress_jkr, JKRError
    from .crypto import is_encrypted_file, decrypt, CryptoError

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


def read_multi_pointer_entries(
    bfile: BinaryFile,
    start_position: int,
    pointers_per_entry: int
) -> list[dict[str, int | str | list[int]]]:
    """
    Read null-terminated multi-pointer entries with correct grouping.

    Each entry has a fixed number of string pointers.  Null internal
    pointers are skipped (they don't carry a string), and the terminator
    is an entry whose **first** pointer is 0.  Sub-strings within a
    single entry are joined in ``text`` with the ``{j}`` marker, and
    their actual pointer-slot offsets (which may be non-contiguous if
    internal slots are null) are recorded in ``sub_offsets``.

    :param bfile: Binary file to read from
    :param start_position: File offset of the first entry
    :param pointers_per_entry: Number of u32 pointers per entry
    :return: List of dicts with ``"offset"``, ``"text"``, and
        ``"sub_offsets"`` keys.
    """
    results: list[dict[str, int | str | list[int]]] = []
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

        sub_texts: list[str] = []
        sub_offsets: list[int] = []
        for i, ptr in enumerate(ptrs):
            if ptr == 0:
                continue
            bfile.validate_offset(
                ptr, context=f"string pointer in entry at 0x{pos:x}"
            )
            bfile.seek(ptr)
            data_stream = read_until_null(bfile)
            text = decode_game_string(
                data_stream, context=f"pointer 0x{ptr:x}"
            )
            sub_texts.append(text)
            sub_offsets.append(pos + i * 4)

        if sub_texts:
            results.append({
                "offset": sub_offsets[0],
                "text": JOIN_MARKER.join(sub_texts),
                "sub_offsets": sub_offsets,
            })

        pos += pointers_per_entry * 4

    return results


def read_struct_strings(
    bfile: BinaryFile,
    base_offset: int,
    entry_count: int,
    entry_size: int,
    field_offset: int | list[int]
) -> list[dict[str, int | str]]:
    """
    Read strings from struct fields at regular intervals.

    Extracts string pointers embedded in repeated structs (e.g., menu
    entries where title/description pointers sit at a fixed offset
    within each struct). ``field_offset`` may be a single int or a list
    of ints when a struct contains multiple string pointer fields; in the
    multi-field case all fields are read per entry (entry-major order).

    :param bfile: Binary file to read from
    :param base_offset: Start address of the struct array in the file
    :param entry_count: Number of structs in the array
    :param entry_size: Size of each struct in bytes
    :param field_offset: Byte offset(s) of string pointer field(s) within
        each struct. int for single-field, list[int] for multi-field.
    :return: List of dicts with "offset" and "text" keys
    """
    if isinstance(field_offset, int):
        field_offsets = [field_offset]
    else:
        field_offsets = list(field_offset)

    results: list[dict[str, int | str]] = []
    for i in range(entry_count):
        entry_base = base_offset + i * entry_size
        for fo in field_offsets:
            pointer_offset = entry_base + fo
            bfile.validate_offset(
                pointer_offset,
                context=f"struct entry {i} field at +0x{fo:x}"
            )
            bfile.seek(pointer_offset)
            pointer = bfile.read_int()
            if pointer == 0:
                continue
            bfile.validate_offset(
                pointer, context=f"string pointer in entry {i} +0x{fo:x}"
            )
            bfile.seek(pointer)
            data_stream = read_until_null(bfile)
            text = decode_game_string(
                data_stream, context=f"struct entry {i} +0x{fo:x}"
            )
            results.append({
                "offset": pointer_offset,
                "text": text,
                "sub_offsets": [pointer_offset],
            })
    return results


def scan_region_for_strings(
    bfile: BinaryFile,
    region_start: int,
    region_end: int,
    min_length: int = 4,
    max_length: int = 400,
    dedupe: bool = True,
) -> list[dict[str, int | str]]:
    """
    Walk every 4-byte aligned slot in [region_start, region_end) and
    emit entries for slots that look like valid string pointers into
    a clean (character-boundary) Shift-JIS string start.

    Used for mixed struct regions where string pointers are interleaved
    with numeric fields and substring references (e.g. mhfgao.bin
    situational dialogue area at header 0x040). Pointers that land mid
    character — where the byte immediately preceding the target is a
    Shift-JIS lead byte — are classified as composition-engine fragments
    and skipped, because their offsets depend on the exact byte layout
    of the original Japanese encoding and would break after translation.

    :param bfile: Binary file to read from
    :param region_start: Inclusive start offset of the region to scan
    :param region_end: Exclusive end offset of the region
    :param min_length: Reject strings shorter than this (bytes)
    :param max_length: Reject strings longer than this (bytes)
    :param dedupe: If True, each unique target pointer is emitted once
        (at its first occurrence). Disable to surface every pointer slot.
    :return: List of dicts with "offset" (the pointer slot location,
        not the string target) and "text" keys
    """
    if region_end <= region_start:
        return []
    bfile.validate_offset(region_start, context="scan_region start")
    bfile.validate_offset(region_end - 1, context="scan_region end")

    file_size = bfile.size
    bfile.seek(region_start)
    data = bfile.read(region_end - region_start)

    results: list[dict[str, int | str]] = []
    seen_targets: set[int] = set()

    for slot_rel in range(0, len(data) - 3, 4):
        pointer = struct.unpack_from("<I", data, slot_rel)[0]
        slot_offset = region_start + slot_rel

        # Filter 1: null / OOB (IDs, flags, counters)
        if pointer == 0 or pointer >= file_size:
            continue

        # Filter 2: mid-multi-byte-character fragment. If the byte
        # preceding the target is a Shift-JIS lead byte (0x81-0x9F or
        # 0xE0-0xFC), the pointer lands on a trail byte — i.e. inside
        # a multi-byte character. These are runtime composition-engine
        # substring references whose offsets depend on the exact byte
        # layout of the original Japanese encoding and would break
        # after translation. (Note: this does NOT filter out "semantic"
        # tail fragments that happen to land on a char boundary — those
        # are indistinguishable from real strings at the byte level.)
        if pointer > 0:
            bfile.seek(pointer - 1)
            prev_byte = bfile.read(1)[0]
            if (0x81 <= prev_byte <= 0x9F) or (0xE0 <= prev_byte <= 0xFC):
                continue

        # Filter 3: read null-terminated span
        bfile.seek(pointer)
        raw = read_until_null(bfile)
        if len(raw) < min_length or len(raw) > max_length:
            continue

        # Filter 4: must decode cleanly as Shift-JIS from the start
        try:
            text = decode_game_string(
                raw, context=f"scan_region slot {slot_offset:#x}"
            )
        except (UnicodeDecodeError, ValueError):
            continue
        if not text:
            continue

        # Filter 5: reject strings that contain Unicode replacement chars
        # (U+FFFD indicates a decode that used error='replace' on invalid
        # Shift-JIS bytes — means we started mid-stream or hit junk, and
        # re-encoding during import/ReFrontier export would fail).
        if "\ufffd" in text:
            continue

        # Filter 6: reject strings whose first decoded char is a C0 control
        # (these are almost always numeric coincidences, not real strings)
        first = text[0]
        if ord(first) < 0x20 and first not in ("\n", "\t"):
            continue

        if dedupe:
            if pointer in seen_targets:
                continue
            seen_targets.add(pointer)

        results.append({
            "offset": slot_offset,
            "text": text,
            "sub_offsets": [slot_offset],
        })

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
            sub_texts: list[str] = []
            sub_offsets: list[int] = []
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
                sub_texts.append(text)
                sub_offsets.append(text_block_ptr + i * 4)
            if sub_texts:
                results.append({
                    "offset": sub_offsets[0],
                    "text": JOIN_MARKER.join(sub_texts),
                    "sub_offsets": sub_offsets,
                })

    return results


def extract_text_data(
    file_path: str,
    config: dict,
    game_version: str = DEFAULT_GAME_VERSION,
) -> list[dict[str, int | str]]:
    """
    Extract text from a game file based on extraction config.

    Supports these extraction modes:
    - Flat pointer array (begin_pointer + entry_count)
    - Struct-strided fields (begin_pointer + entry_count + entry_size)
    - Null-terminated (begin_pointer + null_terminated)
    - Quest table (begin_pointer + quest_table)
    - Scan region (begin_pointer + scan_region)

    Legacy modes (deprecated, will be removed):
    - Standard pointer-pair (begin_pointer + next_field_pointer)
    - Count-based pointer table (begin_pointer + count_pointer)
    - Indirect count (begin_pointer + count_base_pointer)

    :param file_path: Path to the game file
    :param config: Extraction config dict from headers.json
    :param game_version: Game version key for versioned entry_count maps.
    :return: List of dicts with "offset" and "text" keys
    """
    file_data = load_file_data(file_path)
    return extract_text_data_from_bytes(file_data, config, game_version)


def extract_text_data_from_bytes(
    file_data: bytes,
    config: dict,
    game_version: str = DEFAULT_GAME_VERSION,
) -> list[dict[str, int | str]]:
    """
    Extract text from raw binary data based on extraction config.

    Same as :func:`extract_text_data` but takes raw bytes instead of a
    file path. Useful when the data has already been loaded, decrypted,
    or decompressed.

    :param file_data: Raw binary data
    :param config: Extraction config dict from headers.json
    :param game_version: Game version key for versioned entry_count maps.
    :return: List of dicts with "offset" and "text" keys
    :raises ValueError: If config is missing required keys
    """
    if not isinstance(config, dict):
        raise ValueError(
            f"Extraction config must be a dict, got {type(config).__name__}"
        )
    if "begin_pointer" not in config:
        raise ValueError(
            "Extraction config missing required key 'begin_pointer'"
        )

    bfile = BinaryFile.from_bytes(file_data)

    begin_pointer = int(config["begin_pointer"], 16)

    if config.get("scan_region"):
        # Scan mode: walk every 4-byte slot in [begin, end), emit only
        # pointers that land on a clean Shift-JIS char boundary. Used for
        # mixed struct regions interleaved with fragments and numeric IDs.
        scan_end = config.get("scan_end_pointer") or config.get("next_field_pointer")
        if scan_end is None:
            raise ValueError(
                "scan_region mode requires 'scan_end_pointer' (or legacy "
                "'next_field_pointer') to bound the region"
            )
        scan_end_pointer = int(scan_end, 16)
        bfile.seek(begin_pointer)
        region_start = bfile.read_int()
        bfile.seek(scan_end_pointer)
        region_end = bfile.read_int()
        dedupe = config.get("dedupe", True)
        min_length = config.get("min_length", 4)
        max_length = config.get("max_length", 400)
        return scan_region_for_strings(
            bfile, region_start, region_end,
            min_length=min_length,
            max_length=max_length,
            dedupe=dedupe,
        )

    elif "entry_count" in config and "entry_size" in config:
        # Struct-strided: read string pointers at fixed intervals in struct array
        entry_count = resolve_entry_count(config["entry_count"], game_version)
        entry_size = config["entry_size"]
        field_offset = config["field_offset"]

        if config.get("literal_base"):
            # begin_pointer is treated as a literal file offset (no deref)
            base_offset = begin_pointer
        else:
            bfile.seek(begin_pointer)
            base_offset = bfile.read_int()
        return read_struct_strings(
            bfile, base_offset, entry_count, entry_size, field_offset
        )

    elif "entry_count" in config:
        # Flat pointer array: begin_pointer → start, entry_count × ppe pointers
        entry_count = resolve_entry_count(config["entry_count"], game_version)
        pointers_per_entry = config.get("pointers_per_entry", 1)
        if entry_count == 0:
            return []

        bfile.validate_offset(begin_pointer + 3, context="begin_pointer dereference")
        bfile.seek(begin_pointer)
        start_position = bfile.read_int()
        read_length = entry_count * pointers_per_entry * 4
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

    # ── Legacy modes (deprecated) ──────────────────────────────────────
    # These will be removed once all headers.json sections are migrated
    # to entry_count. Kept for backward compatibility during transition.

    elif "next_field_pointer" in config:
        # Standard: pointer pair defining start and end of pointer table
        next_field_pointer = int(config["next_field_pointer"], 16)
        crop_end = config.get("crop_end", 0)

        bfile.validate_offset(begin_pointer + 3, context="begin_pointer dereference")
        bfile.seek(begin_pointer)
        start_position = bfile.read_int()
        bfile.validate_offset(next_field_pointer + 3, context="next_field_pointer dereference")
        bfile.seek(next_field_pointer)
        read_length = bfile.read_int() - start_position - crop_end
        if read_length < 0:
            raise InvalidPointerError(
                f"Negative read length ({read_length}) from pointer chain: "
                f"begin_pointer=0x{begin_pointer:x} -> 0x{start_position:x}, "
                f"next_field_pointer=0x{next_field_pointer:x}, crop_end={crop_end}"
            )
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

    else:
        raise ValueError(
            f"Unknown extraction config format: {list(config.keys())}. "
            f"Expected one of: entry_count, null_terminated, quest_table, "
            f"or scan_region."
        )
