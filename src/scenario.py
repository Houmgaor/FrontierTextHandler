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
import re
import struct
from typing import Callable, Optional

from .binary_file import BinaryFile
from .common import decode_game_string, load_file_data
from .pointer_tables import read_until_null
from .jkr_decompress import JKRHeader, decompress_jkr, is_jkr_file

logger = logging.getLogger(__name__)

# Script bytes the JKR scan takes for text: control characters other than
# tab and line breaks, or bytes that do not decode. No real line has them.
_SCRIPT_BYTES = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ufffd]")


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

    The strings run from the end of the metadata to the 0xFF sentinel (or
    the end of the chunk). entry_count is not their number: in quest
    scenarios chunk1 declares 4 strings but holds about 10 (the quest
    objective and the NPC's replies follow the first 4), and the client
    reaches them through byte offsets in the metadata.

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
    metadata_total = data[chunk_offset + 6]

    # Strings start after sub-header (8 bytes) + metadata
    strings_offset = chunk_offset + 8 + metadata_total
    chunk_end = chunk_offset + chunk_size

    if strings_offset >= chunk_end:
        return []

    return _scan_null_terminated_strings(data, strings_offset, chunk_end)


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
    Parse chunk0 data, auto-detecting JKR, sub-header or inline format.

    Sub-header format: byte[1] == 0x00 (padding byte in sub-header)
    Inline format: byte[1] != 0x00 (first byte of Shift-JIS string)

    :param data: Full file data
    :param chunk_offset: Absolute offset of chunk0 data
    :param chunk_size: Size of chunk0 data in bytes
    :return: List of dicts with "offset" and "text" keys
    """
    if chunk_size < 2:
        return []

    if is_jkr_file(data[chunk_offset:chunk_offset + chunk_size]):
        return _parse_jkr_chunk(data, chunk_offset, chunk_size)
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


JKR_ROW_BASE = 0x100000


def jkr_row_bases(data: bytes) -> dict[int, int]:
    """
    Row-offset base of each JKR-compressed chunk, keyed by its file offset.

    A row inside a compressed chunk is keyed by base + its position in the
    decompressed data. Decompressed chunks are larger than compressed
    ones, so the chunk's own file offset as base made keys of one chunk
    run into the next (a translation for chunk1 landed in chunk2). The
    bases start at JKR_ROW_BASE, past any scenario file (the client takes
    chunks of at most 0x8000 bytes), and follow each other by the
    decompressed sizes in the JKR headers. Those sizes do not change when
    strings are patched in place, so a rebuilt file keeps the same keys.

    :param data: Full scenario file data
    :return: ``{chunk file offset: row base}`` for the JKR chunks
    """
    if len(data) < 8:
        return {}
    c0_size, c1_size = struct.unpack_from(">2I", data, 0)
    chunks = [(8, c0_size), (8 + c0_size, c1_size)]
    c2_header = 8 + c0_size + c1_size
    if c2_header + 4 <= len(data):
        chunks.append((c2_header + 4, struct.unpack_from(">I", data, c2_header)[0]))
    bases: dict[int, int] = {}
    base = JKR_ROW_BASE
    for offset, size in chunks:
        chunk = data[offset:offset + size]
        header = JKRHeader.from_bytes(chunk) if is_jkr_file(chunk) else None
        if header is not None:
            bases[offset] = base
            base += header.decompressed_size
    return bases


def _parse_jkr_chunk(
    data: bytes,
    chunk_offset: int,
    chunk_size: int,
) -> list[dict[str, int | str]]:
    """
    Parse a JKR-compressed chunk by decompressing and scanning for strings.

    The decompressed data contains repeated entries of metadata bytes
    followed by null-terminated Shift-JIS strings.

    Row offsets are the chunk's base from :func:`jkr_row_bases` plus the
    position in the decompressed data.

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

    base = jkr_row_bases(data).get(chunk_offset, chunk_offset)
    return _scan_decompressed_strings(decompressed, base)


def _scan_null_terminated_strings(
    data: bytes,
    start: int,
    end: int,
) -> list[dict[str, int | str]]:
    """
    Scan for null-terminated Shift-JIS strings in a byte range.

    :param data: Full file data
    :param start: Start offset (inclusive)
    :param end: End offset (exclusive)
    :return: List of dicts with "offset" and "text" keys
    """
    results: list[dict[str, int | str]] = []
    pos = start

    while pos < end:
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
        # Also ~ (0x7E) for color codes: the game stores ‾CNN (0x7E 'C' NN),
        # surfaced as {cNN}/{/c} in translation CSVs. See common.color_codes_to_csv.
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
                # Skip dialogue-script bytes that happen to look like text
                if not _SCRIPT_BYTES.search(text):
                    # Use base_offset + string position for unique offset
                    results.append({
                        "offset": base_offset + string_start,
                        "text": text,
                    })

        # Skip null terminator
        if pos < length:
            pos += 1

    return results


# The client keeps each chunk in a fixed 0x8000-byte buffer and drops
# larger ones (FUN_11525c60 in mhfo-hd.dll, per Erupe's scenario notes).
CHUNK_SIZE_LIMIT = 0x8000


def relocate_subheader_chunk(
    chunk: bytes,
    chunk_offset: int,
    translations: dict[int, str],
    encode: Callable[[str], bytes],
) -> Optional[bytes]:
    """
    Rewrite a sub-header chunk's strings at any length.

    The client finds the strings through offsets from the start of the
    strings section: m[5] (the offset of string 1) in chunk0's 0x14-byte
    metadata, m[8]..m[17] in chunk1's 0x2C-byte metadata (negative values
    point after the 0xFF sentinel instead). Across Erupe's 145,376
    scenario files, every chunk1 string is one of those targets, chunk1's
    m[21] is ``chunk size - 8 - 0x2C + 4``, and the header's TotalSize
    covers the chunk (or runs to the sentinel). So the strings are
    re-encoded back to back, empty ones kept; the offsets that point at a
    string are moved with it; TotalSize and m[21] follow the size change;
    the bytes from the sentinel on are kept as they are.

    :param chunk: The chunk bytes (sub-header format)
    :param chunk_offset: The chunk's file offset (row keys are
        ``chunk_offset + position``)
    :param translations: ``{row offset: new text}``
    :param encode: Encodes a string to game bytes (without the NUL)
    :return: The new chunk, or None when it cannot be rewritten safely
        (unknown metadata layout, or larger than CHUNK_SIZE_LIMIT)
    """
    meta_size = chunk[6]
    strings_base = 8 + meta_size
    if meta_size not in (0x14, 0x2C) or strings_base > len(chunk):
        return None

    # The strings section: NUL-terminated strings (some empty) up to the
    # 0xFF sentinel or the end of the chunk.
    new_strings = bytearray()
    moved: dict[int, int] = {}  # old offset -> new offset, from strings_base
    pos = strings_base
    while pos < len(chunk) and chunk[pos] != 0xFF:
        end = chunk.find(b"\x00", pos)
        terminator = b"\x00"
        if end < 0:
            end, terminator = len(chunk), b""
        moved[pos - strings_base] = len(new_strings)
        key = chunk_offset + pos
        if pos < end and key in translations:
            new_strings += encode(translations[key])
        else:
            new_strings += chunk[pos:end]
        new_strings += terminator
        pos = end + 1
    strings_end = min(pos, len(chunk))
    moved[strings_end - strings_base] = len(new_strings)
    delta = len(new_strings) - (strings_end - strings_base)

    out = bytearray(chunk[:strings_base]) + new_strings + chunk[strings_end:]
    if len(out) > CHUNK_SIZE_LIMIT:
        return None

    total_size = struct.unpack_from("<H", chunk, 2)[0]
    if total_size >= strings_end:
        struct.pack_into("<H", out, 2, total_size + delta)
    if meta_size == 0x14:
        fields = [5]
    else:
        fields = list(range(8, 18))
        m21 = struct.unpack_from("<H", chunk, 8 + 2 * 21)[0]
        if m21 == len(chunk) - 8 - meta_size + 4:
            struct.pack_into("<H", out, 8 + 2 * 21, len(out) - 8 - meta_size + 4)
        elif delta:
            return None
    for k in fields:
        value = struct.unpack_from("<H", chunk, 8 + 2 * k)[0]
        if value < 0x8000 and value in moved:
            struct.pack_into("<H", out, 8 + 2 * k, moved[value])
        elif value < 0x8000 and delta:
            # A non-negative offset that is not a string start: we cannot
            # tell where it should go.
            return None
    return bytes(out)


def rebuild_inline_chunk(
    chunk: bytes,
    chunk_offset: int,
    translations: dict[int, str],
    encode: Callable[[str], bytes],
) -> bytes:
    """
    Rewrite an inline chunk0 ({u8 index}{string}{00}...) at any length.

    Entries follow each other with no offsets to them, so each string is
    re-encoded in place of the old one and the rest is copied.

    :param chunk: The chunk bytes (inline format)
    :param chunk_offset: The chunk's file offset
    :param translations: ``{row offset: new text}``
    :param encode: Encodes a string to game bytes (without the NUL)
    :return: The new chunk
    """
    out = bytearray()
    pos = 0
    while pos < len(chunk):
        if chunk[pos] == 0x00:
            out.append(0)
            pos += 1
            continue
        out.append(chunk[pos])  # index byte
        pos += 1
        end = chunk.find(b"\x00", pos)
        if end < 0:
            end = len(chunk)
        key = chunk_offset + pos
        if pos < end and key in translations:
            out += encode(translations[key])
        else:
            out += chunk[pos:end]
        if end < len(chunk):
            out.append(0)
        pos = end + 1
    return bytes(out)


# chunk2 (menu options and quest titles), decompressed: records of a
# 17-byte header (a u32 id, then zeros) followed by two strings (title,
# description). All 61,389 chunk2s in Erupe's bin/scenarios read exactly
# this way, with no lengths or offsets in the headers.
CHUNK2_RECORD_HEADER = 17


def rebuild_chunk2_records(
    decompressed: bytes,
    base: int,
    translations: dict[int, str],
    encode: Callable[[str], bytes],
) -> Optional[bytes]:
    """
    Rewrite decompressed chunk2 records with strings of any length.

    :param decompressed: The decompressed chunk2
    :param base: Row-offset base of the chunk (:func:`jkr_row_bases`)
    :param translations: ``{row offset: new text}``
    :param encode: Encodes a string to game bytes (without the NUL)
    :return: The new decompressed chunk, or None when the data is not a
        sequence of such records or the result exceeds CHUNK_SIZE_LIMIT
    """
    out = bytearray()
    pos = 0
    while pos < len(decompressed):
        if pos + CHUNK2_RECORD_HEADER > len(decompressed):
            return None
        out += decompressed[pos:pos + CHUNK2_RECORD_HEADER]
        pos += CHUNK2_RECORD_HEADER
        for _ in range(2):
            end = decompressed.find(b"\x00", pos)
            if end < 0:
                return None
            key = base + pos
            if pos < end and key in translations:
                out += encode(translations[key])
            else:
                out += decompressed[pos:end]
            out.append(0)
            pos = end + 1
    if len(out) > CHUNK_SIZE_LIMIT:
        return None
    return bytes(out)
