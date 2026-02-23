# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FrontierTextHandler extracts and reimports text from Monster Hunter Frontier binary game files. It reads pointer-based string tables from game data (mhfdat.bin, mhfpac.bin, mhfinf.bin), exports to CSV for translation editing, and writes modified strings back to the binary.

**Key features:**
- Automatic ECD/EXF decryption on read
- Automatic JPK/JKR decompression on read
- Optional compression and encryption on write
- No external dependencies - uses only Python standard library

## Commands

```bash
# Extract all sections defined in headers.json
python main.py --extract-all

# Extract specific data section (auto-decrypts and decompresses)
python main.py --xpath=dat/armors/legs
python main.py --xpath=dat/weapons/melee/name
python main.py --xpath=pac/skills/description

# Insert translations back to binary
python main.py --csv-to-bin output/dat-armors-legs.csv data/mhfdat.bin

# Insert with compression (JKR HFI)
python main.py --csv-to-bin output/dat-armors-legs.csv data/mhfdat.bin --compress

# Insert with compression AND encryption (ready for game)
python main.py --csv-to-bin output/dat-armors-legs.csv data/mhfdat.bin --compress --encrypt

# Decrypt a file manually
python main.py --decrypt data/mhfdat.bin output/mhfdat-decrypted.bin
python main.py --decrypt data/mhfdat.bin output/mhfdat-decrypted.bin --save-meta

# Compare strings between two files
python main.py file_a.csv --diff file_b.csv
python main.py data/mhfdat.bin --diff data/mhfdat_v2.bin --xpath=dat/armors/head

# Validate a game file's structure (encryption, compression, format)
python main.py --validate data/mhfdat.bin

# Merge translations from old CSV/JSON into freshly extracted CSV/JSON
python main.py old_translated.csv --merge new_extracted.csv
python main.py old_translated.json --merge new_extracted.json
python main.py old_translated.csv --merge new_extracted.csv output/merged.csv

# Convert ReFrontier TSV format to standard CSV
python main.py --refrontier-to-csv input.csv output.csv

# Run all tests
python -m unittest discover -v

# Show help
python main.py --help
```

## Architecture

**Data flow:**
```
Encrypted (ECD) → Decrypted → Compressed (JPK) → Decompressed → Extract strings → CSV → Edit → Reimport → Compress → Encrypt → Game-ready
```

**Key modules in `src/`:**
- `common.py` - Core parsing: reads pointer tables and decodes Shift-JIS strings (auto-decrypts and decompresses)
- `export.py` - Extracts data sections and writes CSV (UTF-8) or ReFrontier format (Shift-JIS TSV)
- `import_data.py` - Parses edited CSV and appends new strings to binary, updating pointers
- `binary_file.py` - Context manager for binary file I/O (supports in-memory data via `from_bytes()`)
- `transform.py` - Format conversion between ReFrontier and standard CSV
- `diff.py` - String comparison between two files (CSV or binary)
- `merge.py` - Translation carryover between old translated and freshly extracted files
- `crypto.py` - ECD/EXF encryption and decryption
- `jkr_decompress.py` - JPK/JKR decompression (RW, LZ, HFI, HFIRW types)
- `jkr_compress.py` - JPK/JKR compression (all 4 compression types)

**Configuration (`headers.json`):**
Defines pointer offsets for each data section. Structure: `{file_type}/{category}/{subcategory}` with:
- `begin_pointer`: Hex offset to a pointer that points to the start of the pointer table
- `next_field_pointer`: Hex offset to a pointer that points to the end of the pointer table
- `crop_end`: Optional bytes to exclude from end (for padding/metadata, default: 0)

Note: These are pointers-to-pointers. The file stores addresses that point to the actual table boundaries.

## CSV Format

```csv
location,source,target
0x64@mhfdat.bin,Original Japanese,New Translation
```

- `location`: Pointer offset in hex @ filename
- `source`: Original string (for reference)
- `target`: New string (only imported if different from source)

## String Encoding

Game files use Shift-JIS (specifically Shift-JISX0213). The tool handles encoding/decoding automatically.

## Binary Modification Strategy

New strings are appended to the end of the binary file and pointer values are updated to reference the new locations. This avoids size constraints of in-place replacement.

## JPK/JKR Compression

Built-in support for Monster Hunter Frontier's JPK compression format. JPK files are automatically detected and decompressed when reading game data.

**Compression types:**
- RW (0): Raw, no compression
- HFIRW (2): Huffman encoding only
- LZ (3): LZ77 compression only
- HFI (4): Huffman + LZ77 (most common)

**Public API:**
```python
from src import decompress_jkr, compress_jkr_hfi, is_jkr_file, CompressionType

# Detection and decompression
if is_jkr_file(data):
    decompressed = decompress_jkr(data)

# Compression (HFI recommended)
compressed = compress_jkr_hfi(data)
```

**File format:**
- Magic: `0x1A524B4A` ("JKR\x1A")
- 16-byte header: magic (4) + version (2) + type (2) + data_offset (4) + decompressed_size (4)
- Compressed data follows header

## ECD/EXF Encryption

Built-in support for Monster Hunter Frontier's ECD and EXF encryption formats. Encrypted files are automatically detected and decrypted when reading game data.

**Encryption types:**
- ECD (0x1A646365): Primary format, LCG-based with nibble Feistel cipher
- EXF (0x1A667865): Alternative format, 16-byte XOR key with position-dependent transform

**Key indices:** All known MHF files use key index 4 (the default). Keys 0-5 are available but rarely used.

**Public API:**
```python
from src import decrypt, encrypt, is_encrypted_file, encode_ecd, decode_ecd

# Detection and decryption
if is_encrypted_file(data):
    decrypted, header = decrypt(data)

# Encryption (uses default key 4)
encrypted = encrypt(data)

# Encryption with specific key
encrypted = encrypt(data, key_index=2)

# Re-encryption preserving original format
encrypted = encrypt(data, meta=original_header)
```

**File format:**
- ECD Magic: `0x1A646365` ("ecd\x1A")
- EXF Magic: `0x1A667865` ("exf\x1A")
- 16-byte header: magic (4) + key_index (2) + padding (2) + payload_size (4) + crc32 (4)
- Encrypted payload follows header
