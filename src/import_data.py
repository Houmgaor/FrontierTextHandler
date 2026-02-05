"""
Import data from a CSV file to a binary file.
"""
import codecs
import csv
import os
import shutil

from .binary_file import BinaryFile
from . import common


def get_new_strings(input_file):
    """
    Get the new strings define in a CSV file.

    :param str input_file: Input CSV file path.
    :return list: New strings defined in the file
    """
    new_strings = []
    # First save the strings to insert
    with open(input_file, "r", newline="", encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile)
        common.skip_csv_header(reader, input_file)
        for line in reader:
            # Check is line is not empty and that the translation is different from source
            if not line or line[1] == line[2]:
                continue
            index = int(line[0][:line[0].index("@")], 16)
            new_strings.append([index, line[2]])
    return new_strings


def append_to_binary(new_strings, pointers_change, output_file):
    """
    Edit data in a binary file by appending to the end.

    :param new_strings: New strings to append
    :param tuple[int] pointers_change: Tuple of pointer to change
    :param str output_file: Binary file to edit
    :return:
    """
    with BinaryFile(output_file, "r+b") as bfile:
        for new_value, pointer_offset in zip(new_strings, pointers_change):
            # Append new string
            bfile.seek(0, os.SEEK_END)
            # Edit the pointer to the new position
            new_pointer = bfile.tell()
            bfile.write(codecs.encode(new_value[1], "shift_jisx0213") + b"\x00")

            bfile.seek(pointer_offset)
            print(f"Assigned value {new_pointer} at offset {pointer_offset}")
            bfile.write_int(new_pointer)


def import_from_csv(input_file, output_file):
    """Use the CSV file to edit the binary file."""
    new_strings = get_new_strings(input_file)
    print(f"Found {len(new_strings)} translations to write")
    pointers_to_update = []

    with BinaryFile(output_file) as bfile:
        for candidate in new_strings:
            bfile.seek(candidate[0])
            pointers_to_update.append(candidate[0])

    new_output = "output/mhfdat-modified.bin"
    shutil.copyfile(output_file, new_output)
    append_to_binary(new_strings, tuple(pointers_to_update), new_output)
    print(f"Wrote output to {new_output}. ")
