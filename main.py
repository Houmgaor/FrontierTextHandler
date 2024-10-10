"""
Binary file exporter/importer for Monster Hunter Frontier.

Files need to be decrypted and decompressed with a tool like ReFrontier.
"""

import argparse
import os
import codecs
import json
from zlib import crc32
import csv
import warnings
import shutil

from binary_file import BinaryFile


def parse_inputs():
    """Parse console arguments."""
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
        help="Convert from ReFrontier format (TSV, Shift-JIS) to CSV format.",
    )
    parser.add_argument(
        "--csv-to-bin",
        action="store_true",
        help="Convert from a CSV file (UTF-8) to your binary file.",
    )
    return parser


def read_json_data(xpath="dat/armor/head"):
    """
    Read data from a JSON file.

    :param str xpath: Data path as an XPATH.
    For instance, "dat/armor/head" to get 'headers.json'["dat"]["armors"]["head"].
    :return tuple[int, int, int]: Begin pointer, end pointer and crop before end
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
    """
    Read data until we meet null terminator or end of file.

    :param binary_file.BinaryFile bfile: File to read from
    :return bytes: Data read as a binary stream
    """
    stream = b""
    byte = bfile.read(1)
    while byte != b"\x00" and byte != b"":
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
    """
    Read a part of a file and return strings found.

    :param bfile: Binary file to read from
    :param int start_position: Initial position to read from
    :param int length: Number of bytes to read.
    :return list[tuple[int, str]]: Read a full section."""
    strings = []
    offset = start_position
    while offset < length:
        # Move the file pointer to the desired start position
        bfile.seek(offset)
        strings.append((offset, read_next_string(bfile)))
        offset += 4
    return strings


def read_from_pointers(file_path, pointers_data):
    """
    Read data using pointer headers.

    :param str file_path: Input file path
    :param tuple[int, int, int] pointers_data: Pointers indicated where to read.
    :return list[str]: Found strings with offsets
    """
    start_pointer = pointers_data[0]
    next_field_pointer = pointers_data[1]
    crop_end = pointers_data[2]

    with BinaryFile(file_path) as bfile:
        # Check for proper header first
        header = bfile.read(3)
        if header == b"ecd":
            warnings.warn(
                f"'{file_path}' starts with an ECD header, meaning it's encrypted. "
                + "Make sure to decrypt the file using ReFrontier before using it."
            )
        elif header == b"jpk":
            warnings.warn(
                f"'{file_path}' starts with a JPK header, meaning it's compressed. "
                + "Make sure to decompress the file using ReFrontier before using it."
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


def rewrite_binary_in_place(new_strings, pointers_change, bfile):
    raise NotImplementedError("The binary file cannot be edited in place yet!")
    # Change the strings first (lower in file)
    for new_value in new_strings[::-1]:
        bfile.seek(new_value[2])
        bfile.write(codecs.encode(new_value[1], "shift_jisx0213"))
    # Change the pointer locations
    for p_change in pointers_change:
        bfile.seek(p_change[0])
        print(f"old {p_change[0]} new {p_change[0] + p_change[1]}")
        bfile.write(int.to_bytes(p_change[0] + p_change[1], 4, "little"))


def append_to_binary(new_strings, pointers_change, bfile):
    """Edit data in a binary file by appending to the end."""
    # Change the strings first (lower in file)
    for i, new_value in enumerate(new_strings):
        bfile.seek(0, os.SEEK_END)
        bfile.write(codecs.encode(new_value[1], "shift_jisx0213") + b"\x00")
        pointers_change[i] = pointers_change[i][0], bfile.tell()
    # Change the pointer locations
    for p_change in pointers_change:
        bfile.seek(p_change[0])
        print(f"old {p_change[0]} new {p_change[1]}")
        bfile.write(int.to_bytes(p_change[1], 4, "little"))


def import_from_csv(input_file, output_file, rewrite_in_place=False):
    """Use the CSV file to edit the binary file."""
    new_strings = []
    # First save the strings to insert
    with open(input_file, "r", newline="", encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile)
        # Header should be ["location", "source", "target"]
        try:
            next(reader)
        except StopIteration as _exc:
            raise InterruptedError(f"{input_file} has less than one line!") from _exc
        for line in reader:
            index = int(line[0][:line[0].index("@")])
            new_strings.append([index, line[1]])
    print(f"Found {len(new_strings)} translations to write")
    # Check for new pointers value
    pointers_change = []
    current_offset = 0

    with BinaryFile(output_file) as bfile:
        for candidate in new_strings:
            # Go to pointer referencing this string
            bfile.seek(candidate[0])
            # Save the final pointer
            candidate.append(bfile.read_int())
            # Get the string referenced
            if rewrite_in_place:
                if current_offset != 0:
                    pointers_change.append((candidate[0], current_offset))
                bfile.seek(candidate[0])
                current = read_next_string(bfile)
                old_length = len(codecs.encode(current, "shift_jisx0213"))
                new_length = len(codecs.encode(candidate[1], "shift_jisx0213"))
                if old_length != new_length:
                    print(f"Old: {current}, new: {candidate[1]}, reference {hex(candidate[0])}")
                    current_offset += new_length - old_length
            else:
                # Always change pointers when adding content to file's end
                pointers_change.append((candidate[0], current_offset))
    # Update the new reference positions
    print(pointers_change)

    new_output = "output/mhfdat-modified.bin"
    shutil.copyfile(output_file, new_output)
    with open(new_output, "r+b") as bfile:
        if rewrite_in_place:
            rewrite_binary_in_place(new_strings, pointers_change, bfile)
        else:
            append_to_binary(new_strings, pointers_change, bfile)
    print(f"{new_output} successfully rewrote. ")


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
    elif args.csv_to_bin:
        import_from_csv(args.input_file, args.output_file)
    else:
        # Default: read and save as CSV
        extract_from_file(args.input_file, args.xpath, args.output_file)


if __name__ == "__main__":
    main(parse_inputs().parse_args())
