"""
Manipulation of the extracted data.
"""
import csv
import os

from . import common
from . import export


def import_from_refrontier(input_file):
    """Import data with a ReFrontier format."""
    with open(input_file, "r", newline="\n", encoding="shift_jisx0213") as refrontier_csv:
        reader = csv.reader(refrontier_csv, delimiter="\t", quoting=csv.QUOTE_MINIMAL)
        common.skip_csv_header(reader, input_file)
        for line in reader:
            string = line[2]
            for standard, escaped in common.REFRONTIER_REPLACEMENTS:
                string = string.replace(escaped, standard)
            yield {"offset": int(line[0]), "text": string}


def refrontier_to_csv(input_file, output_file):
    """Take a file with ReFrontier format, converts it to standard CSV."""
    data = import_from_refrontier(input_file)
    export.export_as_csv(data, output_file, os.path.basename(input_file))
