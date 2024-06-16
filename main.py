"""
Binary file exporter/importer for Monster Hunter Frontier.

Files need to be decrypted and decompressed with a tool like ReFrontier.
"""

import os
import codecs
import argparse
import json
from zlib import crc32
import csv
import warnings

from binary_file import BinaryFile


# Console arguments
parser = argparse.ArgumentParser(
    prog="FrontierTextConverter",
    description="Converts strings from Monster Hunter Frontier "
    + "between ReFrontier and other formats.",
)
parser.add_argument(
    "input_file", type=str, default="data/mhfdat.bin", nargs="?", help="Input file."
)
parser.add_argument(
    "output_file",
    type=str,
    default="output/minimal.csv",
    nargs="?",
    help="Output file name.",
)
parser.add_argument(
    "--xpath",
    type=str,
    default="dat/armors/head",
    required=False,
    help="Which data to get, as an xpath. "
    + "For instance 'dat/armors/head' to read from mhfDAT.bin ARMORS HELMETS",
)
parser.add_argument(
    "--refrontier-to-csv",
    action="store_true",
    help="Convert from ReFrontier format (TSV, SHift-JIS) to CSV format.",
)


def read_json_data(xpath="dat/armor/head"):
    """
    Read data from a JSON file.

    :param str xpath: Data path as an XPATH.
    For instance, "dat/armor/head" to get 'headers.json'["dat"]["armors"]["head"].
    """
    path = xpath.split("/")
    with open("headers.json", encoding="utf-8") as f:
        data = json.load(f)
        pointers = data
        for part in path:
            pointers = pointers[part]
        crop_end = 0
        if "crop_end" in pointers:
            crop_end = pointers["crop_end"]
        return (
            int(pointers["begin_pointer"], 16),
            int(pointers["next_field_pointer"], 16),
            crop_end,
        )


def read_until_null(bfile):
    """Read data until we meet null terminator or end of file."""
    stream = b""
    byte = bfile.read(1)
    while byte != b"\x00":
        stream += byte
        byte = bfile.read(1)
    return stream


def read_next_string(bfile):
    """Read a string from a position."""
    pointer = bfile.read_int()
    bfile.seek(pointer)
    data_stream = read_until_null(bfile)
    string = codecs.decode(data_stream, "shift_jisx0213")
    string.replace("\n", "<NL>")
    return string


def read_file_section(bfile, start_position, length):
    """Read a part of a file and return strings found."""
    strings = []
    offset = 0
    bfile.seek(start_position)
    while start_position + offset < length:
        # Move the file pointer to the desired start position
        bfile.seek(start_position + offset)
        strings.append((start_position + offset, read_next_string(bfile)))
        offset += 4
    return strings


def read_from_pointers(file_path, pointers_data):
    """Read data using pointer headers."""
    start_pointer = pointers_data[0]
    next_field_pointer = pointers_data[1]
    crop_end = pointers_data[2]

    with BinaryFile(file_path) as bfile:
        if bfile.read(3) == b"ecd":
            warnings.warn(
                f"'{file_path}' starts with an ECD header, meaning it's encrypted. "
                + "Make sure to decrypt the file using ReFrontier before trying to use it."
            )
        # Move the file pointer to the desired start position
        bfile.seek(start_pointer)
        start_position = bfile.read_int()
        bfile.seek(next_field_pointer)
        end_position = bfile.read_int() - crop_end
        strings = read_file_section(bfile, start_position, end_position)

    return strings


def export_as_csv(data, output_file, source=""):
    """
    Export data in a CSV file with standard compatibility format.


    :param typing.Iterable data: Extracted strings, format is usually (offset, string)
    :param str output_file: Output file path
    :param str source: Eventual file source
    :return:
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
                [string_elem[0], crc32(codecs.encode(string, "shift_jisx0213")), string]
            )
            lines += 1
    print(f"Wrote {lines} lines of ReFrontier compatible file as {output_file}")


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
    export_as_csv(data, output_file, os.path.basename(input_file))


def extract_from_file(input_file, xpath, output_file):
    """Extract data from a single file."""
    # Read data
    pointers_data = read_json_data(xpath)
    file_section = read_from_pointers(input_file, pointers_data)

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


def main(args):
    """Main function to read everything."""
    if not os.path.exists(args.input_file):
        raise FileNotFoundError(
            f"'{args.input_file}' does not exist. You need to import it first."
        )

    if args.refrontier_to_csv:
        refrontier_to_csv(args.input_file, args.output_file)
    else:
        extract_from_file(args.input_file, args.xpath, args.output_file)


if __name__ == "__main__":
    main(parser.parse_args())
