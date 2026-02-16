# Changelog

All notable changes to FrontierTextHandler will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-02-16

### Added
- **ECD/EXF encryption support**: Full round-trip encryption and decryption for Monster Hunter Frontier's encrypted file formats
  - `crypto.py`: ECD encryption (LCG-based nibble Feistel cipher) and EXF encryption (16-byte XOR key)
  - Supports all 6 key indices (all known MHF files use key index 4)
  - Ported from ReFrontier C#
- **Automatic ECD/EXF decryption**: `read_from_pointers()` now auto-detects and decrypts encrypted files before decompression
- **CLI encryption options**: `--encrypt`, `--decrypt`, `--key-index`, `--save-meta` arguments
- **Public API exports**: `decrypt`, `encrypt`, `decode_ecd`, `encode_ecd`, `decode_exf`, `encode_exf`, `is_encrypted_file`, `CryptoError`
- **Test suite**: 50 unit tests for crypto in `tests/test_crypto.py`
- **JPK/JKR compression support**: Full round-trip compression and decompression for Monster Hunter Frontier's JPK format
  - `jkr_decompress.py`: Decompression for all 4 compression types (RW, HFIRW, LZ, HFI)
  - `jkr_compress.py`: Compression for all 4 types with Huffman and LZ77 encoding
  - Ported from MHFrontier-Blender-Addon (originally from ReFrontier C#)
- **Automatic JPK decompression**: `read_from_pointers()` now auto-detects and decompresses JPK files
- **In-memory binary handling**: `BinaryFile.from_bytes()` class method for working with decompressed data
- **Public API exports**: `decompress_jkr`, `compress_jkr`, `compress_jkr_hfi`, `compress_jkr_raw`, `is_jkr_file`, `CompressionType`
- **Test suite**: 54 unit tests for JPK codec in `tests/test_jkr.py`

### Changed
- `common.py`: Now auto-decrypts and decompresses files (decrypt → decompress pipeline)
- `import_data.py`: Added `encrypt` and `key_index` parameters to `import_from_csv()`
- `main.py`: Added CLI arguments for encryption workflow
- `binary_file.py`: Added `from_bytes()` for in-memory data support
- Updated README.md and CLAUDE.md with encryption and compression documentation

### Removed
- Dependency on ReFrontier for the complete text editing workflow (decrypt, decompress, extract, import, compress, encrypt)
