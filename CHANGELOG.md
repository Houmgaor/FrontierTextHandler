# Changelog

All notable changes to FrontierTextHandler will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **JPK/JKR compression support**: Full round-trip compression and decompression for Monster Hunter Frontier's JPK format
  - `jkr_decompress.py`: Decompression for all 4 compression types (RW, HFIRW, LZ, HFI)
  - `jkr_compress.py`: Compression for all 4 types with Huffman and LZ77 encoding
  - Ported from MHFrontier-Blender-Addon (originally from ReFrontier C#)
- **Automatic JPK decompression**: `read_from_pointers()` now auto-detects and decompresses JPK files
- **In-memory binary handling**: `BinaryFile.from_bytes()` class method for working with decompressed data
- **Public API exports**: `decompress_jkr`, `compress_jkr`, `compress_jkr_hfi`, `compress_jkr_raw`, `is_jkr_file`, `CompressionType`
- **Test suite**: 54 unit tests for JPK codec in `tests/test_jkr.py`

### Changed
- `common.py`: Now imports and uses JPK decompression instead of just warning about compressed files
- `binary_file.py`: Added `from_bytes()` for in-memory data support
- Updated README.md and CLAUDE.md with JPK compression documentation

### Removed
- Dependency on ReFrontier for JPK decompression (ECD decryption still requires ReFrontier)
