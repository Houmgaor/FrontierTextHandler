"""
Definition of the FrontierTextHandler module.
"""

__version__ = "1.1.0"

from .export import (
    export_as_json,
    extract_from_file,
    extract_all,
    extract_ftxt_file,
    extract_quest_files,
    extract_single_quest_file,
    extract_npc_dialogue_file,
    extract_npc_dialogue_files,
)
from .transform import refrontier_to_csv
from .import_data import (
    import_from_csv,
    import_ftxt_from_csv,
    import_npc_dialogue_from_csv,
    get_new_strings_from_json,
    get_new_strings_auto,
    CSVParseError,
)
from .common import (
    EncodingError,
    encode_game_string,
    decode_game_string,
    GAME_ENCODING,
    load_file_data,
    read_extraction_config,
    extract_text_data,
    extract_text_data_from_bytes,
    is_ftxt_file,
    extract_ftxt,
    extract_ftxt_data,
    extract_quest_file,
    extract_quest_file_data,
    extract_npc_dialogue,
    extract_npc_dialogue_data,
    QUEST_TEXT_LABELS,
)
from .binary_file import InvalidPointerError
from .jkr_decompress import decompress_jkr, is_jkr_file, CompressionType, JKRError
from .jkr_compress import compress_jkr, compress_jkr_hfi, compress_jkr_raw
from .crypto import (
    CryptoError,
    is_ecd_file,
    is_exf_file,
    is_encrypted_file,
    decode_ecd,
    encode_ecd,
    decode_exf,
    encode_exf,
    decrypt,
    encrypt,
)
