"""
Export data from a binary file to another format (usually CSV).
"""
import csv
import json
import logging
import zlib
import os
from typing import Iterable

from . import common
from .common import (
    encode_game_string,
    GAME_ENCODING,
    color_codes_to_csv,
)
from .scenario import extract_scenario_file as _extract_scenario


def _to_csv_form(text: str) -> str:
    """
    Apply all on-disk escape transforms to an extracted string.

    Since 1.6.0 this only rewrites inline color codes (``‾CNN`` →
    ``{cNN}``/``{/c}``) — the grouped-entry ``{j}`` marker is already
    produced directly by the extractors, so there is no join rewrite
    left to do here.
    """
    return color_codes_to_csv(text)

logger = logging.getLogger(__name__)


def export_as_csv(
    data: Iterable[dict[str, int | str]],
    output_file: str,
    location_name: str = "",
    with_index: bool = True,
) -> int:
    """
    Export data in a CSV file with standard compatibility format.

    :param data: Extracted strings, format is usually {"offset": offset, "text": string}
    :param output_file: Output file path
    :param location_name: File in which to find the source
    :param with_index: If True (the default since 1.6.0), write the
        index-keyed format ``index,source,target`` — three columns, no
        offset/filename. The index is the slot in the section's
        pointer table and is stable across upstream string-length
        changes that would shift raw offsets. If False, write the
        legacy ``location,source,target`` format for backward
        compatibility (the pre-1.6.0 default, still selectable via
        ``--legacy-offset`` on the CLI).
    :return: Number of lines written
    """
    lines = 0
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        if with_index:
            writer.writerow(["index", "source", "target"])
            for index, datum in enumerate(data):
                display = _to_csv_form(str(datum["text"]))
                writer.writerow([index, display, display])
                lines += 1
        else:
            writer.writerow(["location", "source", "target"])
            for datum in data:
                display = _to_csv_form(str(datum["text"]))
                writer.writerow([
                    f"0x{datum['offset']:x}@{location_name}",
                    display,
                    display,
                ])
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
    :raises EncodingError: If a string cannot be encoded to Shift-JIS
    """
    lines = 0
    with open(output_file, "w", encoding=GAME_ENCODING) as csvfile:
        writer = csv.writer(csvfile, delimiter="\t", quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["Offset", "Hash", "JString"])
        for datum in data:
            string = str(datum["text"])
            for standard, escaped in common.REFRONTIER_REPLACEMENTS:
                string = string.replace(standard, escaped)
            encoded = encode_game_string(string, context=f"offset {datum['offset']}")
            writer.writerow(
                [datum["offset"], zlib.crc32(encoded), string]
            )
            lines += 1
    logger.info("Wrote %d lines of ReFrontier compatible file as %s", lines, output_file)
    return lines


def export_as_json(
    data: Iterable[dict[str, int | str]],
    output_file: str,
    location_name: str = "",
    with_index: bool = True,
    xpath: str = "",
    fingerprint: str = "",
) -> int:
    """
    Export data as a JSON file with metadata.

    :param data: Extracted strings, format is usually {"offset": offset, "text": string}
    :param output_file: Output file path
    :param location_name: File in which to find the source
    :param with_index: If True (the default since 1.6.0), write the
        index-keyed format. Entries are ``{index, source, target}``
        and the source binary / xpath live in ``metadata`` instead of
        being repeated per-row. If False, write the legacy
        ``{location, source, target}`` entries for backward
        compatibility.
    :param xpath: Section xpath to record in metadata (index-keyed mode only).
    :param fingerprint: Optional binary fingerprint to record in metadata
        (index-keyed mode only). Used by the importer to detect when a
        translation file is being applied to a different binary version.
    :return: Number of entries written
    """
    from . import __version__

    strings = []
    if with_index:
        for index, datum in enumerate(data):
            display = _to_csv_form(str(datum["text"]))
            strings.append({
                "index": index,
                "source": display,
                "target": display,
            })
    else:
        for datum in data:
            display = _to_csv_form(str(datum["text"]))
            strings.append({
                "location": f"0x{datum['offset']:x}@{location_name}",
                "source": display,
                "target": display,
            })

    metadata = {
        "source_file": location_name,
        "version": __version__,
    }
    if with_index and xpath:
        metadata["xpath"] = xpath
    if with_index and fingerprint:
        metadata["fingerprint"] = fingerprint

    output = {
        "metadata": metadata,
        "strings": strings,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    count = len(strings)
    logger.info("Wrote %d entries of JSON as %s", count, output_file)
    return count


def extract_ftxt_file(
    input_file: str,
    output_file: str = "",
    output_dir: str = "output",
    with_index: bool = True,
) -> tuple[str, str, str]:
    """
    Extract text from an FTXT standalone text file.

    :param input_file: Path to the FTXT file
    :param output_file: Output file path (auto-generated if empty)
    :param output_dir: Directory for output files
    :param with_index: If True (the default since 1.6.0), write the
        index-keyed CSV/JSON format. False selects the legacy
        offset-keyed format for backward compatibility.
    :return: Tuple of (csv_path, refrontier_path, json_path)
    """
    file_section = common.extract_ftxt(input_file)

    if not file_section:
        raise ValueError(f"No text found in FTXT file '{input_file}'.")

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info("Created new folder '%s'", output_dir)

    if not output_file:
        basename = os.path.splitext(os.path.basename(input_file))[0]
        output_file = os.path.join(output_dir, f"ftxt-{basename}.csv")

    refrontier_path = os.path.join(output_dir, "refrontier.csv")
    json_path = os.path.splitext(output_file)[0] + ".json"

    export_as_csv(
        file_section, output_file, os.path.basename(input_file),
        with_index=with_index,
    )
    export_for_refrontier(file_section, refrontier_path)
    export_as_json(
        file_section, json_path, os.path.basename(input_file),
        with_index=with_index,
    )

    return output_file, refrontier_path, json_path


def _batch_extract(
    input_dir: str,
    output_dir: str,
    label: str,
    prefix: str,
    extract_fn,
    export_json: bool = False,
    with_index: bool = True,
) -> list[str]:
    """
    Shared batch extraction helper.

    Iterates over .bin files in *input_dir*, calls *extract_fn(filepath)*
    for each, and exports the results.

    :param input_dir: Directory containing .bin files
    :param output_dir: Directory for output files
    :param label: Human-readable label for log messages (e.g., "quest")
    :param prefix: Filename prefix for output CSV (e.g., "quest")
    :param extract_fn: Callable(filepath) → list[dict] of extracted entries
    :param export_json: If True, also export a JSON file per input file
    :param with_index: If True (the default since 1.6.0), write the
        index-keyed CSV/JSON format. False selects the legacy
        offset-keyed format.
    :return: List of generated CSV file paths
    """
    if not os.path.isdir(input_dir):
        raise FileNotFoundError(
            f"{label.capitalize()} directory '{input_dir}' not found."
        )

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    generated = []
    skipped = 0

    for filename in sorted(os.listdir(input_dir)):
        if not filename.endswith(".bin"):
            continue
        filepath = os.path.join(input_dir, filename)
        try:
            file_section = extract_fn(filepath)
            if not file_section:
                logger.debug("No text in %s '%s', skipping", label, filename)
                skipped += 1
                continue

            basename = os.path.splitext(filename)[0]
            csv_path = os.path.join(output_dir, f"{prefix}-{basename}.csv")
            export_as_csv(
                file_section, csv_path, filename, with_index=with_index,
            )
            if export_json:
                json_path = os.path.join(output_dir, f"{prefix}-{basename}.json")
                export_as_json(
                    file_section, json_path, filename,
                    with_index=with_index,
                )
            generated.append(csv_path)
            logger.info("Extracted %s '%s' to '%s'", label, filename, csv_path)
        except (ValueError, common.EncodingError) as exc:
            logger.warning("Failed to extract %s '%s': %s", label, filename, exc)
            skipped += 1

    logger.info(
        "%s extraction complete: %d files, %d skipped",
        label.capitalize(), len(generated), skipped
    )
    return generated


def extract_quest_files(
    quest_dir: str,
    output_dir: str = "output",
    quest_type_flags_offset: int = 0x00,
    quest_strings_offset: int = 0xE8,
    text_pointers_count: int = 8,
    with_index: bool = True,
) -> list[str]:
    """
    Batch extract text from all quest .bin files in a directory.

    :param quest_dir: Directory containing quest .bin files
    :param output_dir: Directory for output files
    :param quest_type_flags_offset: Offset of questTypeFlagsPtr in quest header
    :param quest_strings_offset: Offset of QuestStringsPtr in main quest props
    :param text_pointers_count: Number of string pointers per quest (default 8)
    :param with_index: If True (the default since 1.6.0), write the
        index-keyed CSV/JSON format. False selects the legacy
        offset-keyed format for backward compatibility.
    :return: List of generated CSV file paths
    """
    def _extract(filepath):
        return common.extract_quest_file(
            filepath, quest_type_flags_offset,
            quest_strings_offset, text_pointers_count
        )

    return _batch_extract(
        quest_dir, output_dir, "quest", "quest", _extract,
        with_index=with_index,
    )


def extract_single_quest_file(
    input_file: str,
    output_file: str = "",
    output_dir: str = "output",
    quest_type_flags_offset: int = 0x00,
    quest_strings_offset: int = 0xE8,
    text_pointers_count: int = 8,
    with_index: bool = True,
) -> tuple[str, str, str]:
    """
    Extract text from a single quest .bin file.

    :param input_file: Path to the quest .bin file
    :param output_file: Output file path (auto-generated if empty)
    :param output_dir: Directory for output files
    :param quest_type_flags_offset: Offset of questTypeFlagsPtr in quest header
    :param quest_strings_offset: Offset of QuestStringsPtr in main quest props
    :param text_pointers_count: Number of string pointers per quest (default 8)
    :param with_index: If True (the default since 1.6.0), write the
        index-keyed CSV/JSON format. False selects the legacy
        offset-keyed format for backward compatibility.
    :return: Tuple of (csv_path, refrontier_path, json_path)
    """
    file_section = common.extract_quest_file(
        input_file, quest_type_flags_offset,
        quest_strings_offset, text_pointers_count
    )

    if not file_section:
        raise ValueError(f"No text found in quest file '{input_file}'.")

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    if not output_file:
        basename = os.path.splitext(os.path.basename(input_file))[0]
        output_file = os.path.join(output_dir, f"quest-{basename}.csv")

    refrontier_path = os.path.join(output_dir, "refrontier.csv")
    json_path = os.path.splitext(output_file)[0] + ".json"

    export_as_csv(
        file_section, output_file, os.path.basename(input_file),
        with_index=with_index,
    )
    export_for_refrontier(file_section, refrontier_path)
    export_as_json(
        file_section, json_path, os.path.basename(input_file),
        with_index=with_index,
    )

    return output_file, refrontier_path, json_path


def extract_npc_dialogue_file(
    input_file: str,
    output_file: str = "",
    output_dir: str = "output",
    with_index: bool = True,
) -> tuple[str, str, str]:
    """
    Extract NPC dialogue text from a stage dialogue binary file.

    :param input_file: Path to the dialogue file
    :param output_file: Output file path (auto-generated if empty)
    :param output_dir: Directory for output files
    :param with_index: If True, write the 1.6.0 index-keyed CSV/JSON
        format. Defaults to False for standalone file formats because
        the matching import path doesn't yet resolve index keys;
        passing True works but the resulting file can't be round-
        tripped through ``import_from_csv`` without also teaching the
        importer about the file's layout.
    :return: Tuple of (csv_path, refrontier_path, json_path)
    """
    file_section = common.extract_npc_dialogue(input_file)

    if not file_section:
        raise ValueError(f"No NPC dialogue found in '{input_file}'.")

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info("Created new folder '%s'", output_dir)

    if not output_file:
        basename = os.path.splitext(os.path.basename(input_file))[0]
        output_file = os.path.join(output_dir, f"npc-{basename}.csv")

    refrontier_path = os.path.join(output_dir, "refrontier.csv")
    json_path = os.path.splitext(output_file)[0] + ".json"

    export_as_csv(
        file_section, output_file, os.path.basename(input_file),
        with_index=with_index,
    )
    export_for_refrontier(file_section, refrontier_path)
    export_as_json(
        file_section, json_path, os.path.basename(input_file),
        with_index=with_index,
    )

    return output_file, refrontier_path, json_path


def extract_npc_dialogue_files(
    npc_dir: str,
    output_dir: str = "output",
    with_index: bool = True,
) -> list[str]:
    """
    Batch extract NPC dialogue from all .bin files in a directory.

    :param npc_dir: Directory containing stage dialogue .bin files
    :param output_dir: Directory for output files
    :param with_index: If True (the default), write the 1.6.0
        index-keyed CSV/JSON format. False selects the legacy
        offset-keyed format.
    :return: List of generated CSV file paths
    """
    return _batch_extract(
        npc_dir, output_dir, "NPC dialogue", "npc",
        common.extract_npc_dialogue,
        with_index=with_index,
    )


def extract_scenario_file(
    input_file: str,
    output_file: str = "",
    output_dir: str = "output",
    with_index: bool = True,
) -> tuple[str, str, str]:
    """
    Extract text from a single scenario .bin file.

    :param input_file: Path to the scenario file
    :param output_file: Output file path (auto-generated if empty)
    :param output_dir: Directory for output files
    :param with_index: If True, write the 1.6.0 index-keyed CSV/JSON
        format. Defaults to False for standalone file formats because
        the matching import path doesn't yet resolve index keys;
        passing True works but the resulting file can't be round-
        tripped through ``import_from_csv`` without also teaching the
        importer about the file's layout.
    :return: Tuple of (csv_path, refrontier_path, json_path)
    """
    file_section = _extract_scenario(input_file)

    if not file_section:
        raise ValueError(f"No text found in scenario file '{input_file}'.")

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info("Created new folder '%s'", output_dir)

    if not output_file:
        basename = os.path.splitext(os.path.basename(input_file))[0]
        output_file = os.path.join(output_dir, f"scenario-{basename}.csv")

    refrontier_path = os.path.join(output_dir, "refrontier.csv")
    json_path = os.path.splitext(output_file)[0] + ".json"

    export_as_csv(
        file_section, output_file, os.path.basename(input_file),
        with_index=with_index,
    )
    export_for_refrontier(file_section, refrontier_path)
    export_as_json(
        file_section, json_path, os.path.basename(input_file),
        with_index=with_index,
    )

    return output_file, refrontier_path, json_path


def extract_scenario_files(
    scenario_dir: str,
    output_dir: str = "output",
    with_index: bool = True,
) -> list[str]:
    """
    Batch extract text from all scenario .bin files in a directory.

    :param scenario_dir: Directory containing scenario .bin files
    :param output_dir: Directory for output files
    :param with_index: If True (the default), write the 1.6.0
        index-keyed CSV/JSON format. False selects the legacy
        offset-keyed format.
    :return: List of generated CSV file paths
    """
    return _batch_extract(
        scenario_dir, output_dir, "scenario", "scenario",
        _extract_scenario, export_json=True,
        with_index=with_index,
    )


DEFAULT_OUTPUT_DIR = "output"

# Mapping of file type prefixes to their default input files
FILE_TYPE_DEFAULTS = {
    "dat": "data/mhfdat.bin",
    "pac": "data/mhfpac.bin",
    "inf": "data/mhfinf.bin",
    "jmp": "data/mhfjmp.bin",
    "nav": "data/mhfnav.bin",
    "gao": "data/mhfgao.bin",
    "rcc": "data/mhfrcc.bin",
    "msx": "data/mhfmsx.bin",
    "sqd": "data/mhfsqd.bin",
}


def extract_from_file(
    input_file: str,
    xpath: str,
    output_file: str,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    headers_path: str = common.DEFAULT_HEADERS_PATH,
    with_index: bool = True,
) -> tuple[str, str, str]:
    """
    Extract data from a single file.

    :param input_file: Input file path
    :param xpath: String selection xpath
    :param output_file: Output file path (used as fallback if xpath not provided)
    :param output_dir: Directory for output files
    :param headers_path: Path to headers.json configuration file
    :param with_index: If True (the default since 1.6.0), write the
        index-keyed CSV/JSON format. False selects the legacy
        offset-keyed format for backward compatibility.
    :return: Tuple of (csv_path, refrontier_path, json_path) for the exported files
    """
    # Read data using config-based extraction (supports all formats).
    # Load the file once so we can reuse the bytes for fingerprinting
    # rather than reading the file twice.
    config = common.read_extraction_config(xpath, headers_path)
    file_data = common.load_file_data(input_file)
    file_section = common.extract_text_data_from_bytes(file_data, config)
    fingerprint = common.compute_binary_fingerprint(file_data) if with_index else ""

    if not file_section:
        raise ValueError(
            f"Cannot find any readable data in '{input_file}' with xpath '{xpath}'. "
            + "Double-check the file format, name and xpath provided."
        )
    # Ensure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info("Created new folder '%s'", output_dir)

    # Determine output filenames
    if xpath:
        export_name = os.path.join(output_dir, xpath.replace("/", "-") + ".csv")
    else:
        export_name = output_file

    refrontier_path = os.path.join(output_dir, "refrontier.csv")
    json_path = os.path.splitext(export_name)[0] + ".json"

    export_as_csv(
        file_section, export_name, os.path.basename(input_file),
        with_index=with_index,
    )
    export_for_refrontier(file_section, refrontier_path)
    export_as_json(
        file_section, json_path, os.path.basename(input_file),
        with_index=with_index, xpath=xpath, fingerprint=fingerprint,
    )

    return export_name, refrontier_path, json_path


def extract_all(
    input_files: dict[str, str] = None,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    headers_path: str = common.DEFAULT_HEADERS_PATH,
    with_index: bool = True,
) -> list[str]:
    """
    Extract all sections defined in headers.json.

    :param input_files: Dict mapping file type prefixes to input file paths.
        If None, uses FILE_TYPE_DEFAULTS.
    :param output_dir: Directory for output files
    :param headers_path: Path to headers.json configuration file
    :param with_index: If True (the default since 1.6.0), write the
        index-keyed CSV/JSON format. False selects the legacy
        offset-keyed format for backward compatibility.
    :return: List of generated CSV file paths
    """
    if input_files is None:
        input_files = FILE_TYPE_DEFAULTS.copy()

    xpaths = common.get_all_xpaths(headers_path)
    generated_files = []
    skipped_count = 0

    for xpath in xpaths:
        # Determine which input file to use based on xpath prefix
        file_type = xpath.split("/")[0]
        input_file = input_files.get(file_type)

        if input_file is None:
            logger.warning(
                "No input file configured for type '%s', skipping xpath '%s'",
                file_type, xpath
            )
            skipped_count += 1
            continue

        if not os.path.exists(input_file):
            logger.warning(
                "Input file '%s' not found, skipping xpath '%s'",
                input_file, xpath
            )
            skipped_count += 1
            continue

        try:
            csv_path, _, _ = extract_from_file(
                input_file, xpath, "", output_dir, headers_path,
                with_index=with_index,
            )
            generated_files.append(csv_path)
            logger.info("Extracted '%s' to '%s'", xpath, csv_path)
        except (ValueError, FileNotFoundError) as exc:
            logger.warning("Failed to extract '%s': %s", xpath, exc)
            skipped_count += 1

    logger.info(
        "Batch extraction complete: %d files generated, %d skipped",
        len(generated_files), skipped_count
    )
    return generated_files
