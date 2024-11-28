"""
Import data from a CSV file to a binary file.
"""
import codecs
import csv
import os
import shutil
import warnings

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
        # Header should be ["location", "source", "target"]
        try:
            next(reader)
        except StopIteration as _exc:
            raise InterruptedError(f"{input_file} has less than one line!") from _exc
        for line in reader:
            # Check is line is not empty and that the translation is different from source
            if not line or line[1] == line[2]:
                continue
            index = int(line[0][:line[0].index("@")])
            new_strings.append([index, line[2]])
    return new_strings


def rewrite_binary_in_place(new_strings, pointers_change, output_file):
    """
    Rewrite the binary file by changing the strings in place.

    :param new_strings: New strings to insert
    :param pointers_change: List of changes, initial pointer value, new pointer value
    :type pointers_change: list[tuple[int, int]]
    :param str output_file: Binary file to edit
    """
    warnings.warn(
        "Function not finished! "
        "It will break your file if the replacement strings have a number of characters "
        "different from the initial strings."
    )
    with BinaryFile(output_file, "r+b") as bfile:
        # Change the strings first (lower in file)
        for new_value in new_strings[::-1]:
            bfile.seek(new_value[2])
            bfile.write(codecs.encode(new_value[1], "shift_jisx0213"))
        # Change the pointer locations
        for p_change in pointers_change:
            bfile.seek(p_change[0])
            print(f"old {p_change[0]} new {p_change[0] + p_change[1]}")
            bfile.write_int(p_change[0] + p_change[1])


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


def import_from_csv(input_file, output_file, rewrite_in_place=False):
    """Use the CSV file to edit the binary file."""
    new_strings = get_new_strings(input_file)
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
                current = common.read_next_string(bfile)
                old_length = len(codecs.encode(current, "shift_jisx0213"))
                new_length = len(codecs.encode(candidate[1], "shift_jisx0213"))
                if old_length != new_length:
                    print(f"Old: {current}, new: {candidate[1]}, reference {hex(candidate[0])}")
                    current_offset += new_length - old_length
            else:
                # Always change pointers when adding content to file's end
                pointers_change.append((candidate[0], None))
    # Update the new reference positions
    new_output = "output/mhfdat-modified.bin"
    shutil.copyfile(output_file, new_output)
    if rewrite_in_place:
        rewrite_binary_in_place(new_strings, pointers_change, new_output)
    else:
        append_to_binary(new_strings, tuple(p[0] for p in pointers_change), new_output)
    print(f"Wrote output to {new_output}. ")
