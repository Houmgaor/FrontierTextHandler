# -*- coding: utf-8 -*-
"""
JKR/JPK decompression for Monster Hunter Frontier files.

Ported from ReFrontier (C#) by Houmgaor.
Adapted for FrontierTextHandler.

Supports 4 compression types:
- Type 0 (RW): Raw, no compression
- Type 1 (HFIRW): Huffman encoding only
- Type 2 (LZ): LZ77 compression
- Type 3 (HFI): Huffman + LZ77 compression
"""

import struct
from dataclasses import dataclass
from enum import IntEnum
from io import BytesIO
from typing import Optional


class JKRError(ValueError):
    """Raised when JKR/JPK decompression fails."""
    pass


class CompressionType(IntEnum):
    """JKR compression types."""
    RW = 0      # Raw (no compression)
    NONE = 1    # Special type for "no compression"
    HFIRW = 2   # Huffman only
    LZ = 3      # LZ77
    HFI = 4     # Huffman + LZ77


# JKR magic bytes: "JKR\x1A" (little endian: 0x1A524B4A)
JKR_MAGIC = 0x1A524B4A

# JKR header constants
JKR_HEADER_SIZE = 16        # Size of JKR header in bytes
JKR_DEFAULT_VERSION = 0x108  # Default version number

# Huffman decoding constants
# Boundary between leaf nodes (0-255) and internal tree nodes (256+)
HUFFMAN_LEAF_THRESHOLD = 0x100
# Base offset for Huffman table navigation: (node * 2 - 0x200 + bit) * 2
HUFFMAN_TABLE_BASE = 0x200
# Offset adjustment for calculating data start: table_len * 4 - 0x3FC
HUFFMAN_DATA_OFFSET_ADJ = 0x3FC

# LZ77 decoding constants
# Bit masks for extracting values from hi/lo bytes
LZ_LENGTH_MASK = 0xE0       # Upper 3 bits of hi byte contain length
LZ_LENGTH_SHIFT = 5         # Shift to extract length from hi byte
LZ_OFFSET_HI_MASK = 0x1F    # Lower 5 bits of hi byte contain offset high bits
# Length constants for back-reference cases
LZ_BASE_LENGTH_LONG = 0x1A  # Base length for Case 3/4 (26)
LZ_LITERAL_RUN_BASE = 0x1B  # Base length for literal run (27)
LZ_LITERAL_RUN_MARKER = 0xFF  # Marker byte indicating literal run mode


@dataclass
class JKRHeader:
    """JKR file header structure."""
    magic: int              # 4 bytes: 0x1A524B4A ("JKR\x1A")
    version: int            # 2 bytes: usually 0x108
    compression_type: int   # 2 bytes: compression type enum
    data_offset: int        # 4 bytes: offset to compressed data
    decompressed_size: int  # 4 bytes: size after decompression

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional["JKRHeader"]:
        """
        Parse JKR header from bytes.

        :param data: At least 16 bytes of header data.
        :return: Parsed header or None if invalid magic.
        """
        if len(data) < JKR_HEADER_SIZE:
            return None

        magic, version, compression_type, data_offset, decompressed_size = struct.unpack(
            "<IHHII", data[:JKR_HEADER_SIZE]
        )

        if magic != JKR_MAGIC:
            return None

        return cls(
            magic=magic,
            version=version,
            compression_type=compression_type,
            data_offset=data_offset,
            decompressed_size=decompressed_size,
        )


def _copy_back(out: bytearray, index: int, distance: int, length: int) -> None:
    """Copy *length* bytes to ``out[index:]`` from *distance* bytes back."""
    start = index - distance
    if start < 0 or index + length > len(out):
        raise JKRError(
            f"LZ back-reference outside the output: {length} byte(s) from "
            f"{distance} back at {index} (output size {len(out)})"
        )
    if distance >= length:
        out[index:index + length] = out[start:start + length]
    else:
        # Overlapping copy: the last *distance* bytes repeat.
        pattern = out[start:index]
        out[index:index + length] = (pattern * (length // distance + 1))[:length]


def _lz_decode(src: bytes, pos: int, out_size: int) -> bytes:
    """
    Decode the LZ77 stage of JPK types 3 (LZ) and 4 (HFI).

    Ported from ReFrontier JPKDecodeLz.cs. Control bits come MSB first
    from flag bytes interleaved with the data bytes in *src*. Like the
    game's decoder, running out of input ends decoding early, leaving the
    rest of the output zeroed.

    :param src: Byte stream (raw file data, or HFI's Huffman-decoded bytes).
    :param pos: Offset of the first byte in *src*.
    :param out_size: Decompressed size from the JKR header.
    """
    out = bytearray(out_size)
    index = 0
    flag = 0
    shift = 0  # Bit of *flag* last used; 0 means "read a new flag byte".
    # The control-bit read is written out inline: this loop runs once per
    # token and a helper call per bit would dominate the running time.
    try:
        while index < out_size:
            if shift:
                shift -= 1
            else:
                shift = 7
                flag = src[pos]
                pos += 1
            if not (flag >> shift) & 1:
                out[index] = src[pos]
                pos += 1
                index += 1
                continue

            if shift:
                shift -= 1
            else:
                shift = 7
                flag = src[pos]
                pos += 1
            if not (flag >> shift) & 1:
                # Case 0: 2-bit length, 1-byte offset.
                length = 0
                for _ in range(2):
                    if shift:
                        shift -= 1
                    else:
                        shift = 7
                        flag = src[pos]
                        pos += 1
                    length = (length << 1) | ((flag >> shift) & 1)
                offset = src[pos]
                pos += 1
                _copy_back(out, index, offset + 1, length + 3)
                index += length + 3
                continue

            hi = src[pos]
            lo = src[pos + 1]
            pos += 2
            length = (hi & LZ_LENGTH_MASK) >> LZ_LENGTH_SHIFT
            offset = ((hi & LZ_OFFSET_HI_MASK) << 8) | lo
            if length:
                # Case 1: 3-bit length in the high byte.
                _copy_back(out, index, offset + 1, length + 2)
                index += length + 2
                continue

            if shift:
                shift -= 1
            else:
                shift = 7
                flag = src[pos]
                pos += 1
            if not (flag >> shift) & 1:
                # Case 2: 4-bit length.
                length = 0
                for _ in range(4):
                    if shift:
                        shift -= 1
                    else:
                        shift = 7
                        flag = src[pos]
                        pos += 1
                    length = (length << 1) | ((flag >> shift) & 1)
                _copy_back(out, index, offset + 1, length + 2 + 8)
                index += length + 2 + 8
                continue

            temp = src[pos]
            pos += 1
            if temp == LZ_LITERAL_RUN_MARKER:
                # Case 3: literal run.
                run = offset + LZ_LITERAL_RUN_BASE
                if index + run > out_size:
                    raise JKRError(
                        f"LZ literal run of {run} byte(s) at {index} overflows "
                        f"the output size {out_size}"
                    )
                chunk = src[pos:pos + run]
                out[index:index + len(chunk)] = chunk
                index += len(chunk)
                pos += len(chunk)
                if len(chunk) < run:
                    break  # Input ran out mid-run.
                continue

            # Case 4: long back-reference.
            _copy_back(out, index, offset + 1, temp + LZ_BASE_LENGTH_LONG)
            index += temp + LZ_BASE_LENGTH_LONG
    except IndexError:
        pass  # Input ran out: keep what was decoded, as the game does.
    return bytes(out)


def _huffman_decode(data: bytes, pos: int) -> bytes:
    """
    Decode the Huffman stage of JPK types 2 (HFIRW) and 4 (HFI).

    Ported from ReFrontier's JpkGetHf. At *pos*: an int16 root node id,
    then the tree as int16 child pairs (node *n* has children at
    ``2 * n - 0x200`` and the next slot), then the bit stream, MSB first,
    up to the end of *data*. Ids below ``HUFFMAN_LEAF_THRESHOLD`` are
    leaves holding a byte.

    Rather than walking the tree bit by bit, this decodes a whole input
    byte per step: from a given node, a byte always yields the same symbols
    and ends on the same node. Those transitions are computed on first use
    and cached.

    :return: Every symbol in the stream (a trailing partial code is dropped).
    """
    root = struct.unpack_from("<h", data, pos)[0]
    table_offset = pos + 2
    data_offset = table_offset + root * 4 - HUFFMAN_DATA_OFFSET_ADJ
    if root < HUFFMAN_LEAF_THRESHOLD:
        # Degenerate tree: every symbol is the root, and no bits are read.
        raise JKRError(f"Huffman tree root {root} is a leaf")
    if data_offset < table_offset or data_offset > len(data):
        raise JKRError(f"Huffman tree of root {root} does not fit in the data")
    table = struct.unpack_from(f"<{(data_offset - table_offset) // 2}h", data, table_offset)

    def transition(node: int, byte: int) -> tuple:
        symbols = bytearray()
        for bit in range(7, -1, -1):
            node = table[node * 2 - HUFFMAN_TABLE_BASE + ((byte >> bit) & 1)]
            if node < HUFFMAN_LEAF_THRESHOLD:
                symbols.append(node & 0xFF)
                node = root
        return bytes(symbols), node << 8

    steps = [None] * ((root + 1) << 8)
    parts = []
    state = root << 8
    try:
        for byte in memoryview(data)[data_offset:]:
            step = steps[state | byte]
            if step is None:
                step = steps[state | byte] = transition(state >> 8, byte)
            parts.append(step[0])
            state = step[1]
    except IndexError as exc:
        raise JKRError(f"Huffman tree references a node outside the table: {exc}") from exc
    return b"".join(parts)


class LZDecoder:
    """LZ77 decompression (JPK type 3), reading from a stream."""

    @staticmethod
    def _jpk_copy_lz(buffer: bytearray, offset: int, length: int, index: int) -> int:
        """
        Copy length bytes to buffer at position index.
        Bytes are copied from position index - offset - 1.
        """
        _copy_back(buffer, index, offset + 1, length)
        return length

    def decode(self, in_stream: BytesIO, out_size: int) -> bytes:
        """Decompress the LZ77 data remaining in *in_stream*."""
        return _lz_decode(in_stream.read(), 0, out_size)


class HFIDecoder(LZDecoder):
    """Huffman + LZ77 decompression (JPK type 4), reading from a stream."""

    def decode(self, in_stream: BytesIO, out_size: int) -> bytes:
        """Decompress the Huffman + LZ77 data remaining in *in_stream*."""
        return _lz_decode(_huffman_decode(in_stream.read(), 0), 0, out_size)


class RWDecoder:
    """Raw decoder - no compression."""

    def decode(self, in_stream: BytesIO, out_size: int) -> bytes:
        """Read raw bytes."""
        return in_stream.read(out_size)


class HFIRWDecoder:
    """Huffman-only decompression (JPK type 2), reading from a stream."""

    def decode(self, in_stream: BytesIO, out_size: int) -> bytes:
        """Decompress the Huffman data remaining in *in_stream*."""
        symbols = _huffman_decode(in_stream.read(), 0)
        if len(symbols) < out_size:
            raise JKRError(
                f"Huffman data ends after {len(symbols)} of {out_size} byte(s)"
            )
        return symbols[:out_size]


def decompress_jkr(data: bytes) -> bytes:
    """
    Decompress JKR/JPK compressed data.

    :param data: Raw JKR file data.
    :return: Decompressed data.
    :raises JKRError: If the data is not a valid JKR file or decompression fails.
    """
    if len(data) < JKR_HEADER_SIZE:
        raise JKRError(
            f"Data too short for JKR header: {len(data)} bytes "
            f"(minimum {JKR_HEADER_SIZE} required)"
        )

    header = JKRHeader.from_bytes(data)
    if header is None:
        raise JKRError(
            f"Invalid JKR magic bytes: expected 0x{JKR_MAGIC:08x}, "
            f"got 0x{struct.unpack('<I', data[:4])[0]:08x}"
        )

    try:
        compression_type = CompressionType(header.compression_type)
    except ValueError as exc:
        raise JKRError(
            f"Unknown JKR compression type: {header.compression_type}"
        ) from exc

    decoder = {
        CompressionType.RW: RWDecoder,
        CompressionType.NONE: RWDecoder,  # Same as RW
        CompressionType.HFIRW: HFIRWDecoder,
        CompressionType.LZ: LZDecoder,
        CompressionType.HFI: HFIDecoder,
    }[compression_type]()

    stream = BytesIO(data)
    stream.seek(header.data_offset)
    try:
        return decoder.decode(stream, header.decompressed_size)
    except struct.error as exc:
        raise JKRError(f"Decompression failed: {exc}") from exc


def is_jkr_file(data: bytes) -> bool:
    """
    Check if data starts with JKR magic bytes.

    :param data: Raw file data.
    :return: True if this is a JKR file.
    """
    if len(data) < 4:
        return False
    magic = struct.unpack("<I", data[:4])[0]
    return magic == JKR_MAGIC
