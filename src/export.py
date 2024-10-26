"""
Export data from a binary file to another format (usually CSV).
"""
import csv
import codecs
import zlib
import os

from . import common


def export_as_csv(data, output_file, source=""):
    """
    Export data in a CSV file with standard compatibility format.

    :param typing.Iterable data: Extracted strings, format is usually (offset, string)
    :param str output_file: Output file path
    :param str source: Eventual file source
    """
    lines = 0
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["location", "source", "target"])
        for string_elem in data:
            writer.writerow(
                [str(string_elem[0]) + "@" + source, string_elem[1], string_elem[1]]
            )
            lines += 1
    print(f"Wrote {lines} lines of translation CSV as {output_file}")


def export_for_refrontier(data, output_file):
    """
    Export data in a CSV file with ReFrontier compatible format.

    :param list data: Extracted strings with offsets
    :param str output_file: File path for output.
    :return:
    """
    lines = 0
    with codecs.open(output_file, "w", encoding="shift_jisx0213") as csvfile:
        writer = csv.writer(csvfile, delimiter="\t", quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["Offset", "Hash", "jString"])
        for string_elem in data:
            # Necessary replacement for ReFrontier
            replacements = ("\t", "<TAB>"), ("\r\n", "<CLINE>"), ("\n", "<NLINE>")
            string = string_elem[1]
            for rep in replacements:
                string = string.replace(rep[0], rep[1])
            writer.writerow(
                [string_elem[0], zlib.crc32(codecs.encode(string, "shift_jisx0213")), string]
            )
            lines += 1
    print(f"Wrote {lines} lines of ReFrontier compatible file as {output_file}")


def extract_from_file(input_file, xpath, output_file):
    """Extract data from a single file."""
    # Read data
    pointers_data = common.read_json_data(xpath)
    file_section = common.read_from_pointers(input_file, pointers_data)

    if not file_section:
        raise ValueError(
            f"Cannot find any readable data in '{input_file}' with xpath '{xpath}'. "
            + "Double-check the file format, name and xpath provided."
        )
    # Output
    folder_name = "output"
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        print(f"Created new folder '{folder_name}'.")
    export_name = output_file
    if xpath:
        export_name = "output/" + xpath.replace("/", "-") + ".csv"
    export_as_csv(file_section, export_name, os.path.basename(input_file))
    export_for_refrontier(file_section, "output/refrontier.csv")
