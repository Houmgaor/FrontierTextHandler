"""
Manipulation of the extracted data.
"""
import csv
import os
from typing import Iterator

from . import common
from . import export
from .common import GAME_ENCODING


def import_from_refrontier(input_file: str) -> Iterator[dict[str, int | str]]:
    """
    Import data with a ReFrontier format.

    :param input_file: Path to ReFrontier format CSV (TSV, Shift-JIS encoded)
    :yield: Dict with "offset" (int) and "text" (str) keys
    """
    with open(input_file, "r", newline="\n", encoding=GAME_ENCODING) as refrontier_csv:
        reader = csv.reader(refrontier_csv, delimiter="\t", quoting=csv.QUOTE_MINIMAL)
        common.skip_csv_header(reader, input_file)
        for line in reader:
            string = line[2]
            for standard, escaped in common.REFRONTIER_REPLACEMENTS:
                string = string.replace(escaped, standard)
            yield {"offset": int(line[0]), "text": string}


def refrontier_to_csv(input_file: str, output_file: str) -> int:
    """
    Take a file with ReFrontier format, converts it to standard CSV.

    :param input_file: Path to ReFrontier format file
    :param output_file: Path to output CSV file
    :return: Number of lines written
    """
    data = import_from_refrontier(input_file)
    return export.export_as_csv(data, output_file, os.path.basename(input_file))
