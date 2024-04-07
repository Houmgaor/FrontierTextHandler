# FrontierTextHandler

A utility to read text from Monster Hunter Frontier, edit and reinsert.
It is roughly a Python rewrite of mhvuze work with FrontierTextTool and FrontierDataTool, in Python.

## Install

Download the repository and run command from the main folder.

## Usage

```bash
# This can save lives
python main.py --help
```

To extract the data:

- Get either ``mhfdat.bin``, ``mhfpac.bin`` or ``mhfinf.bin`` from Monster 
Hunter Frontier source code
- Decrypt, decompile with [ReFrontier](https://github.com/mhvuze/ReFrontier). Place the output in ``data/``.
- Run ``main.py``.

Output data will be in ``output/*.csv``. The file ``output/refrontier.csv`` is compatible with ReFrontier.

### Extract specific data

You can customize with data will be extracted. 
For instance to extract only the legs armor names from mhfdat.bin:

```bash
python main.py --xpath=dat/armors/legs
```

It will create a file ``output/dat-armors-legs.csv``.

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
incredible reference for this project.
