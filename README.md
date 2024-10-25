# FrontierTextHandler

A utility to read text from Monster Hunter Frontier, edit and reinsert.
It is roughly a Python rewrite of FrontierTextTool 
(from [ReFrontier](https://github.com/Houmgaor/ReFrontier), by mhvuze) in Python.

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

1. Decrypt, decompile MHFrontier source code with [ReFrontier](https://github.com/Houmgaor/ReFrontier).
2. Place the binary files ``mhfdat.bin``, ``mhfpac.bin`` or ``mhfinf.bin`` in a ``data/`` folder.
3. Run ``main.py``.

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

1. The first column of the file should be the original datum location (with format [offset]@[original file name]).
2. The second column is the original string value.
3. The third column is the new string value.

To update the file, use `--csv-to-bin [input CSV] [output BIN file]`.
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

## Credits

This software was realized with the support of [@ezemania2](https://github.com/ezemania2) from the 
[MezeLounge](https://discord.com/invite/monster-hunter-frontier-eu-973963573619486740) Discord community
as well as the [Mogapédia](https://mogapedia.fandom.com/fr/wiki/Monster_Hunter_Wiki), the French Monster
Hunter wiki.

## See also

- [var-username/Monster-Hunter-Frontier-Patterns](https://github.com/var-username/Monster-Hunter-Frontier-Patterns):
great reference for this project.
