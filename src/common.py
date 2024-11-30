"""
Core module functions.
"""
import codecs
import json
import struct
import warnings

from .binary_file import BinaryFile


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
        if "begin_pointer" not in pointers or "next_field_pointer" not in pointers:
            raise ValueError(
                "Please specify more precise path. Options are: '" +
                ",".join(pointers.keys()) + "'."
            )
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
    return string


def read_file_section(bfile, start_position, length):
    """
    Read a part of a file and return strings found.

    :param bfile: Binary file to read from
    :param int start_position: Initial position to read from
    :param int length: Number of bytes to read.
    :return list[tuple[int, str]]: Read a full section."""
    bfile.seek(start_position)
    pointers_stream = bfile.read(length)
    # Get the list of continuous pointers
    pointers = struct.unpack(f"<{length // 4}I", pointers_stream)
    strings = []
    ids = []
    current_id = 0
    join_lines = 0 in pointers
    for pointer in pointers:
        # Frontier separates some multiline strings (e.g. weapon descriptions)
        # with multiple \x00 paddings
        if join_lines:
            if pointer == 0:
                current_id += 1
                continue
        else:
            current_id += 1
        # Move to string pointer
        bfile.seek(pointer)
        data_stream = read_until_null(bfile)
        strings.append(codecs.decode(data_stream, "shift_jisx0213"))
        ids.append(current_id)

    # Group output by id
    output = []
    last_id = -1
    for offset, string, current_id in zip(
        range(start_position, start_position + length, 4),
        strings,
        ids
    ):
        if current_id == last_id:
            output[-1]["text"] += f'<join at="{offset}">{string}'
        else:
            output.append({"offset": offset, "text": string})
            last_id = current_id
    return output


def read_from_pointers(file_path, pointers_data):
    """
    Read data using pointer headers.

    :param str file_path: Input file path
    :param tuple[int, int, int] pointers_data: Pointers indicated where to read.
    :return dict: Dictionary of "offset", "text" and "id" elements
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
        read_length = bfile.read_int() - start_position - crop_end
        reads = read_file_section(bfile, start_position, read_length)

    return reads
