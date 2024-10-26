"""
Manipulation of the extracted data.
"""
import csv
import os

from . import export


def import_from_refrontier(input_file):
    """Import data with a ReFrontier format."""
    with open(input_file, "r", newline="\n", encoding="shift_jis") as refrontier_csv:
        reader = csv.reader(refrontier_csv, delimiter="\t", quoting=csv.QUOTE_MINIMAL)
        # reader header : ['Offset', 'Hash', 'jString']
        try:
            next(reader)
        except StopIteration as _exc:
            raise InterruptedError(f"{input_file} has less than one line!") from _exc
        for line in reader:
            # Necessary replacement for ReFrontier
            replacements = ("\t", "<TAB>"), ("\r\n", "<CLINE>"), ("\n", "<NLINE>")
            string = line[2]
            for rep in replacements:
                string = string.replace(rep[1], rep[0])
            yield line[0], string


def refrontier_to_csv(input_file, output_file):
    """Take a file with ReFrontier format, converts it to standard CSV."""
    data = import_from_refrontier(input_file)
    export.export_as_csv(data, output_file, os.path.basename(input_file))
