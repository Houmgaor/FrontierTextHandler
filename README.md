# FrontierTextHandler

A utility to read text from Monster Hunter Frontier, edit and reinsert.
It is roughly a Python rewrite of FrontierTextTool
(from [ReFrontier](https://github.com/Houmgaor/ReFrontier), by mhvuze) in Python.

## Requirements

- **Python 3.7+** (uses dataclasses and modern type hints)
- No external dependencies (pure standard library)

## Install

Download the repository and run command from the main folder.
```commandline
git clone https://github.com/Houmgaor/FrontierTextHandler.git
cd FrontierTextHandler
```

## Usage

```bash
# This can save lives
python main.py --help
```

To extract the data:

1. Decrypt MHFrontier source files with [ReFrontier](https://github.com/Houmgaor/ReFrontier).
2. Place the binary files ``mhfdat.bin``, ``mhfpac.bin`` or ``mhfinf.bin`` in a ``data/`` folder.
3. Run ``main.py``.

**Note:** JPK-compressed files are automatically decompressed. You only need to decrypt ECD-encrypted files with ReFrontier first.

Output data will be in ``output/*.csv``. The file ``output/refrontier.csv`` is compatible with ReFrontier.

### Extract specific data

You can customize with data will be extracted. 
For instance to extract only the legs armor names from mhfdat.bin:

```bash
python main.py --xpath=dat/armors/legs
```

It will create a file ``output/dat-armors-legs.csv``.

### Change the game files

Using a CSV file, you can insert new strings (such as translations) in the original MHFrontier game.

The CSV file should follow this convention:

1. The first column (location) of the file should be the original datum location (with format [offset]@[original file name]).
2. The second column (source) is the original string value.
3. The third column (target) is the new string value.

To update the file, use `--csv-to-bin [input CSV] [output BIN file]`.
It will only add strings if "target" is different from "source".
For instance:

```commandline
python main.py --csv-to-bin output/dat-armors-legs.csv data/mhfdat.bin
```

### Compatibility with ReFrontier

You can also convert any translation CSV to ReFrontier

```bash
python main.py --refrontier-to-csv
```

Currently, you can extract all names and descriptions for: weapons, armors, items as well as skills.

## JPK Compression

FrontierTextHandler includes built-in support for JPK/JKR compression, the format used by Monster Hunter Frontier for compressed game files. This removes the dependency on ReFrontier for decompression.

### Automatic Decompression

JPK files are automatically detected and decompressed when reading game data. No additional steps needed.

### Python API

You can also use the compression functions directly in Python:

```python
from src import compress_jkr_hfi, decompress_jkr, is_jkr_file

# Check if a file is JPK compressed
with open("file.bin", "rb") as f:
    data = f.read()
    if is_jkr_file(data):
        decompressed = decompress_jkr(data)

# Compress data (HFI = Huffman + LZ77, most common)
compressed = compress_jkr_hfi(original_data)

# Decompress
original = decompress_jkr(compressed)
```

Supported compression types:
- **RW (0)**: Raw, no compression
- **HFIRW (2)**: Huffman encoding only
- **LZ (3)**: LZ77 compression only
- **HFI (4)**: Huffman + LZ77 (most common, best compression)

### Running Tests

```bash
python -m unittest discover -s tests -v
```

## Troubleshooting

### Common Errors

#### `FileNotFoundError: 'data/mhfdat.bin' does not exist`

The input file was not found. Make sure to:
1. Create a `data/` folder in the project directory
2. Place your decrypted game files (`mhfdat.bin`, `mhfpac.bin`, etc.) in it
3. Verify the file path matches your command

#### `InterruptedError: file.csv has less than one line!`

The CSV file is empty or has no data rows. Ensure your CSV file has:
1. A header row: `location,source,target`
2. At least one data row

#### `EncodingError: Failed to encode string to Shift-JIS`

Your translation contains characters not supported by the game's encoding (Shift-JIS). Common causes:
- Emoji characters
- Special Unicode symbols
- Characters from non-Japanese/ASCII scripts

**Solution:** Replace unsupported characters with ASCII or Japanese equivalents.

#### `CSVParseError: Invalid location format`

The CSV location column is malformed. Expected format: `0x1234@filename.bin`

Check that:
1. The hex offset starts with `0x`
2. There's an `@` separator between offset and filename
3. No extra spaces or characters

#### `ValueError: Cannot find any readable data in 'file.bin' with xpath 'path'`

The xpath doesn't match the file type or the file structure is different. Solutions:
1. Verify you're using the correct xpath for your file (e.g., `dat/` for mhfdat.bin, `pac/` for mhfpac.bin)
2. Check available xpaths in `headers.json`
3. Ensure the file is decrypted (ECD files must be decrypted with ReFrontier first)

#### `Warning: file starts with an ECD header, meaning it's encrypted`

The file is still encrypted. Use [ReFrontier](https://github.com/Houmgaor/ReFrontier) to decrypt it first:

```bash
./ReFrontier mhfdat.bin --decrypt
```

#### `Failed to decompress JPK file`

The JPK file is corrupted or uses an unsupported compression variant. Try:
1. Re-extracting the file from the game data
2. Checking if the file was partially downloaded or truncated

### Debug Mode

Use the `-v` or `--verbose` flag to see detailed debug output:

```bash
python main.py -v data/mhfdat.bin
```

This shows:
- Number of translations found
- Pointer assignments during import
- File creation messages

## Credits

This software was realized with the support of [@ezemania2](https://github.com/ezemania2) from the 
[MezeLounge](https://discord.com/invite/monster-hunter-frontier-eu-973963573619486740) Discord community
as well as the [Mogapédia](https://mogapedia.fandom.com/fr/wiki/Monster_Hunter_Wiki), the French Monster
Hunter wiki.

## See also

- [var-username/Monster-Hunter-Frontier-Patterns](https://github.com/var-username/Monster-Hunter-Frontier-Patterns):
great reference for this project.
