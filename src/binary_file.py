"""
Define BinaryFile class.
"""
import os
import struct
import warnings
from io import BytesIO
from typing import Optional, Union, IO


class InvalidPointerError(ValueError):
    """Raised when a pointer offset is outside the valid file bounds."""
    pass


class BinaryFile:
    """Format for easily manipulation of binary files with pointers."""

    def __init__(
        self,
        file_path: Optional[str] = None,
        mode: str = "rb",
        *,
        _file: Optional[IO[bytes]] = None,
        _size: Optional[int] = None
    ):
        """
        Set properties for the binary file.

        :param file_path: File path (None for in-memory mode)
        :param mode: File opening mode (e.g.: "rb", "r+b")
        :param _file: Internal: pre-opened file object (for from_bytes)
        :param _size: Internal: pre-calculated size (for from_bytes)
        """
        self.file_path = file_path
        self.mode = mode
        self._size = _size

        # Handle in-memory mode (from from_bytes)
        if _file is not None:
            self.file = _file
        else:
            self.file = None
            if mode not in ("rb", "r+b", "wb"):
                warnings.warn(f"Mode '{mode}' is not advised")

    def __enter__(self):
        """Open the binary file context."""
        if self.file is None:
            self.file = open(self.file_path, self.mode)
            # Cache file size for bounds checking
            current_pos = self.file.tell()
            self.file.seek(0, os.SEEK_END)
            self._size = self.file.tell()
            self.file.seek(current_pos)
        return self

    def __exit__(self, *args):
        """Close file on exit."""
        if self.file_path is not None:
            # Only close file-based instances, not BytesIO
            self.file.close()

    @property
    def size(self) -> int:
        """Return the file size in bytes."""
        return self._size

    def read(self, num_bytes):
        """Read num_bytes bytes."""
        return self.file.read(num_bytes)

    def _read_4bytes(self):
        """Read the next 4 bytes as raw bytes (internal helper)."""
        return self.file.read(4)

    def read_int(self):
        """Read next 4 bytes as a little-endian unsigned integer."""
        return struct.unpack("<I", self._read_4bytes())[0]

    def seek(self, offset, seek_type=0):
        """Go to seek point."""
        self.file.seek(offset, seek_type)

    def tell(self):
        """Tell current pointer position."""
        return self.file.tell()

    def write(self, value):
        """Write a value to the file."""
        self.file.write(value)

    def write_int(self, value):
        """Write data as an integer."""
        self.write(struct.pack("<I", value))

    def validate_offset(self, offset: int, context: str = "") -> None:
        """
        Validate that an offset is within the file bounds.

        :param offset: The offset to validate
        :param context: Optional context string for error messages
        :raises InvalidPointerError: If offset is outside file bounds
        """
        if offset < 0 or offset >= self._size:
            ctx = f" ({context})" if context else ""
            raise InvalidPointerError(
                f"Pointer offset 0x{offset:x} is outside file bounds "
                f"(0x0 - 0x{self._size - 1:x}){ctx}"
            )

    @classmethod
    def from_bytes(cls, data: bytes) -> "BinaryFile":
        """
        Create a BinaryFile from in-memory bytes.

        Useful for working with decompressed data without writing to disk.

        :param data: Binary data to wrap.
        :return: BinaryFile instance backed by BytesIO.
        """
        return cls(
            file_path=None,
            mode="rb",
            _file=BytesIO(data),
            _size=len(data)
        )
