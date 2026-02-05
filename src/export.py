"""
Export data from a binary file to another format (usually CSV).
"""
import csv
import codecs
import logging
import zlib
import os
from typing import Iterable

from . import common

logger = logging.getLogger(__name__)


def export_as_csv(
    data: Iterable[dict[str, int | str]],
    output_file: str,
    location_name: str = ""
) -> int:
    """
    Export data in a CSV file with standard compatibility format.

    :param data: Extracted strings, format is usually {"offset": offset, "text": string}
    :param output_file: Output file path
    :param location_name: File in which to find the source
    :return: Number of lines written
    """
    lines = 0
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["location", "source", "target"])
        for datum in data:
            writer.writerow(
                [f"0x{datum['offset']:x}@{location_name}", datum["text"], datum["text"]]
            )
            lines += 1
    logger.info("Wrote %d lines of translation CSV as %s", lines, output_file)
    return lines


def export_for_refrontier(
    data: list[dict[str, int | str]],
    output_file: str
) -> int:
    """
    Export data in a CSV file with ReFrontier compatible format.

    :param data: Extracted strings with offsets
    :param output_file: File path for output.
    :return: Number of lines written
    """
    lines = 0
    with codecs.open(output_file, "w", encoding="shift_jisx0213") as csvfile:
        writer = csv.writer(csvfile, delimiter="\t", quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["Offset", "Hash", "JString"])
        for datum in data:
            string = str(datum["text"])
            for standard, escaped in common.REFRONTIER_REPLACEMENTS:
                string = string.replace(standard, escaped)
            writer.writerow(
                [datum["offset"], zlib.crc32(codecs.encode(string, "shift_jisx0213")), string]
            )
            lines += 1
    logger.info("Wrote %d lines of ReFrontier compatible file as %s", lines, output_file)
    return lines


def extract_from_file(input_file: str, xpath: str, output_file: str) -> None:
    """
    Extract data from a single file.

    :param input_file: Input file path
    :param xpath: String selection xpath
    :param output_file: Output file path
    """
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
        logger.info("Created new folder '%s'", folder_name)
    export_name = output_file
    if xpath:
        export_name = "output/" + xpath.replace("/", "-") + ".csv"
    export_as_csv(file_section, export_name, os.path.basename(input_file))
    export_for_refrontier(file_section, "output/refrontier.csv")
