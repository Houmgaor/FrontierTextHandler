"""
Scenario file parser for Monster Hunter Frontier.

Scenario .bin files contain translatable game text for the story system
(Basic quests, Veteran quests, Diva Exchange, Diva Story).

Container format (big-endian sizes):
    @0x00: u32 BE  chunk0_size  (quest name/description data)
    @0x04: u32 BE  chunk1_size  (NPC dialog data)
    [chunk0_data: chunk0_size bytes]
    [chunk1_data: chunk1_size bytes]
    @(8+c0+c1): u32 BE  chunk2_size  (JKR-compressed menu/title data)
    [chunk2_data: chunk2_size bytes]
"""
import logging
import struct

from .binary_file import BinaryFile
from .common import decode_game_string, load_file_data
from .pointer_tables import read_until_null
from .jkr_decompress import decompress_jkr, is_jkr_file

logger = logging.getLogger(__name__)


def extract_scenario_file(file_path: str) -> list[dict[str, int | str]]:
    """
    Extract text from a scenario .bin file.

    :param file_path: Path to the scenario file (auto-decrypts/decompresses)
    :return: List of dicts with "offset" and "text" keys
    """
    file_data = load_file_data(file_path)
    return extract_scenario_file_data(file_data)


def extract_scenario_file_data(data: bytes) -> list[dict[str, int | str]]:
    """
    Extract text from raw scenario file bytes.

    :param data: Raw scenario file data
    :return: List of dicts with "offset" and "text" keys
    """
    if len(data) < 8:
        return []

    c0_size = struct.unpack_from(">I", data, 0)[0]
    c1_size = struct.unpack_from(">I", data, 4)[0]

    # Validate chunk sizes don't exceed available data
    if c0_size > len(data) - 8:
        logger.warning(
            "Scenario chunk0 size (%d) exceeds available data (%d bytes after header)",
            c0_size, len(data) - 8,
        )
        return []
    if c1_size > len(data) - 8 - c0_size:
        logger.warning(
            "Scenario chunk1 size (%d) exceeds available data (%d bytes remaining)",
            c1_size, len(data) - 8 - c0_size,
        )
        c1_size = 0  # Skip chunk1 but continue with chunk0

    results: list[dict[str, int | str]] = []

    # Parse chunk0 (quest name/description)
    if c0_size > 0:
        c0_offset = 8
        c0_data = data[c0_offset:c0_offset + c0_size]
        results.extend(_parse_chunk0(data, c0_offset, c0_size))

    # Parse chunk1 (NPC dialog or JKR-compressed)
    if c1_size > 0:
        c1_offset = 8 + c0_size
        c1_data = data[c1_offset:c1_offset + c1_size]
        if is_jkr_file(c1_data):
            results.extend(_parse_jkr_chunk(data, c1_offset, c1_size))
        else:
            results.extend(_parse_chunk1(data, c1_offset, c1_size))

    # Parse chunk2 (JKR-compressed menu/title data)
    c2_header_offset = 8 + c0_size + c1_size
    if c2_header_offset + 4 <= len(data):
        c2_size = struct.unpack_from(">I", data, c2_header_offset)[0]
        if c2_size > 0:
            c2_data_offset = c2_header_offset + 4
            if c2_data_offset + c2_size > len(data):
                logger.warning(
                    "Scenario chunk2 size (%d) exceeds available data (%d bytes remaining)",
                    c2_size, len(data) - c2_data_offset,
                )
            else:
                results.extend(
                    _parse_jkr_chunk(data, c2_data_offset, c2_size)
                )

    return results


def _parse_subheader_chunk(
    data: bytes,
    chunk_offset: int,
    chunk_size: int,
) -> list[dict[str, int | str]]:
    """
    Parse a chunk with sub-header format.

    Sub-header (8 bytes):
        type(u8), pad(u8), size(u16 LE), entry_count(u8),
        unk(u8), metadata_total_size(u8), unk(u8)

    :param data: Full file data
    :param chunk_offset: Absolute offset of chunk data in the file
    :param chunk_size: Size of chunk data in bytes
    :return: List of dicts with "offset" and "text" keys
    """
    if chunk_size < 8:
        return []

    # Validate chunk doesn't extend past data
    if chunk_offset + chunk_size > len(data):
        logger.warning(
            "Sub-header chunk at 0x%x (size %d) extends past data (%d bytes)",
            chunk_offset, chunk_size, len(data),
        )
        return []

    # Read sub-header
    entry_count = data[chunk_offset + 4]
    metadata_total = data[chunk_offset + 6]

    # Strings start after sub-header (8 bytes) + metadata
    strings_offset = chunk_offset + 8 + metadata_total
    chunk_end = chunk_offset + chunk_size

    if strings_offset >= chunk_end:
        return []

    return _scan_null_terminated_strings(
        data, strings_offset, chunk_end, entry_count
    )


def _parse_inline_chunk(
    data: bytes,
    chunk_offset: int,
    chunk_size: int,
) -> list[dict[str, int | str]]:
    """
    Parse a chunk with inline entry format: {u8 index}{Shift-JIS string}{00}.

    :param data: Full file data
    :param chunk_offset: Absolute offset of chunk data in the file
    :param chunk_size: Size of chunk data in bytes
    :return: List of dicts with "offset" and "text" keys
    """
    # Validate chunk doesn't extend past data
    if chunk_offset + chunk_size > len(data):
        logger.warning(
            "Inline chunk at 0x%x (size %d) extends past data (%d bytes)",
            chunk_offset, chunk_size, len(data),
        )
        return []

    results: list[dict[str, int | str]] = []
    pos = chunk_offset
    chunk_end = chunk_offset + chunk_size

    while pos < chunk_end:
        # Skip null bytes (padding between entries or at end)
        if data[pos] == 0x00:
            pos += 1
            continue

        # Skip the index byte
        pos += 1
        if pos >= chunk_end:
            break

        # Read null-terminated string
        string_start = pos
        while pos < chunk_end and data[pos] != 0x00:
            pos += 1

        if pos > string_start:
            raw = data[string_start:pos]
            text = decode_game_string(
                raw, context=f"inline entry at 0x{string_start:x}"
            )
            results.append({"offset": string_start, "text": text})

        # Skip null terminator
        if pos < chunk_end:
            pos += 1

    return results


def _parse_chunk0(
    data: bytes,
    chunk_offset: int,
    chunk_size: int,
) -> list[dict[str, int | str]]:
    """
    Parse chunk0 data, auto-detecting sub-header vs inline format.

    Sub-header format: byte[1] == 0x00 (padding byte in sub-header)
    Inline format: byte[1] != 0x00 (first byte of Shift-JIS string)

    :param data: Full file data
    :param chunk_offset: Absolute offset of chunk0 data
    :param chunk_size: Size of chunk0 data in bytes
    :return: List of dicts with "offset" and "text" keys
    """
    if chunk_size < 2:
        return []

    if data[chunk_offset + 1] == 0x00:
        return _parse_subheader_chunk(data, chunk_offset, chunk_size)
    else:
        return _parse_inline_chunk(data, chunk_offset, chunk_size)


def _parse_chunk1(
    data: bytes,
    chunk_offset: int,
    chunk_size: int,
) -> list[dict[str, int | str]]:
    """
    Parse chunk1 (NPC dialog) data with sub-header format.

    :param data: Full file data
    :param chunk_offset: Absolute offset of chunk1 data
    :param chunk_size: Size of chunk1 data in bytes
    :return: List of dicts with "offset" and "text" keys
    """
    return _parse_subheader_chunk(data, chunk_offset, chunk_size)


def _parse_jkr_chunk(
    data: bytes,
    chunk_offset: int,
    chunk_size: int,
) -> list[dict[str, int | str]]:
    """
    Parse a JKR-compressed chunk by decompressing and scanning for strings.

    The decompressed data contains repeated entries of metadata bytes
    followed by null-terminated Shift-JIS strings.

    :param data: Full file data
    :param chunk_offset: Absolute offset of JKR data
    :param chunk_size: Size of JKR data in bytes
    :return: List of dicts with "offset" and "text" keys
    """
    # Validate chunk doesn't extend past data
    if chunk_offset + chunk_size > len(data):
        logger.warning(
            "JKR chunk at 0x%x (size %d) extends past data (%d bytes)",
            chunk_offset, chunk_size, len(data),
        )
        return []

    jkr_data = data[chunk_offset:chunk_offset + chunk_size]
    from .jkr_decompress import JKRError
    try:
        decompressed = decompress_jkr(jkr_data)
    except JKRError as exc:
        logger.warning(
            "Failed to decompress JKR at offset 0x%x: %s", chunk_offset, exc
        )
        return []

    if not decompressed:
        logger.warning(
            "JKR decompression at 0x%x produced empty data", chunk_offset
        )
        return []

    return _scan_decompressed_strings(decompressed, chunk_offset)


def _scan_null_terminated_strings(
    data: bytes,
    start: int,
    end: int,
    max_count: int = 0,
) -> list[dict[str, int | str]]:
    """
    Scan for null-terminated Shift-JIS strings in a byte range.

    :param data: Full file data
    :param start: Start offset (inclusive)
    :param end: End offset (exclusive)
    :param max_count: Maximum number of strings to read (0 = unlimited)
    :return: List of dicts with "offset" and "text" keys
    """
    results: list[dict[str, int | str]] = []
    pos = start
    count = 0

    while pos < end:
        if max_count > 0 and count >= max_count:
            break

        # Skip padding/null bytes
        if data[pos] == 0x00:
            pos += 1
            continue

        # Check for 0xFF marker (end-of-strings sentinel)
        if data[pos] == 0xFF:
            break

        string_start = pos
        while pos < end and data[pos] != 0x00:
            pos += 1

        if pos > string_start:
            raw = data[string_start:pos]
            text = decode_game_string(
                raw, context=f"offset 0x{string_start:x}"
            )
            results.append({"offset": string_start, "text": text})
            count += 1

        # Skip null terminator
        if pos < end:
            pos += 1

    return results


def _scan_decompressed_strings(
    decompressed: bytes,
    base_offset: int,
) -> list[dict[str, int | str]]:
    """
    Scan decompressed JKR data for null-terminated strings.

    Decompressed scenario data has entries with metadata bytes followed by
    null-terminated Shift-JIS strings. We scan through, skipping over
    non-printable metadata and extracting text.

    :param decompressed: Decompressed data
    :param base_offset: File offset of the JKR chunk (for offset recording)
    :return: List of dicts with "offset" and "text" keys
    """
    results: list[dict[str, int | str]] = []
    pos = 0
    length = len(decompressed)

    while pos < length:
        # Skip null/low bytes (metadata)
        if decompressed[pos] == 0x00:
            pos += 1
            continue

        # Try to find start of Shift-JIS text by looking for printable chars
        # Shift-JIS high bytes: 0x81-0x9F, 0xE0-0xEF for lead bytes
        # ASCII printable: 0x20-0x7E
        # Also ~ (0x7E) for color codes like ~C05
        byte = decompressed[pos]
        is_text_start = (
            (0x81 <= byte <= 0x9F)
            or (0xE0 <= byte <= 0xEF)
            or (0x20 <= byte <= 0x7E)
        )

        if not is_text_start:
            pos += 1
            continue

        # Read until null terminator
        string_start = pos
        while pos < length and decompressed[pos] != 0x00:
            pos += 1

        if pos > string_start:
            raw = decompressed[string_start:pos]
            # Only include if it looks like real text (at least a few bytes)
            if len(raw) >= 2:
                text = decode_game_string(
                    raw, context=f"JKR decompressed at 0x{string_start:x}"
                )
                # Use base_offset + string position for unique offset
                results.append({
                    "offset": base_offset + string_start,
                    "text": text,
                })

        # Skip null terminator
        if pos < length:
            pos += 1

    return results
