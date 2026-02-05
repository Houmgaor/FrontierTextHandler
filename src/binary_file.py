"""
Define BinaryFile class.
"""
import os
import struct
import warnings
from io import BytesIO


class InvalidPointerError(ValueError):
    """Raised when a pointer offset is outside the valid file bounds."""
    pass


class BinaryFile:
    """Format for easily manipulation of binary files with pointers."""

    def __init__(self, file_path, mode="rb"):
        """
        Set properties for the binary file.

        :param str file_path: File path
        :param str mode: File opening mode (e.g.: "rb", "r+b")
        """
        self.file_path = file_path
        self.file = None
        self._size = None
        if mode not in ("rb", "r+b", "wb"):
            warnings.warn(f"Mode '{mode}' is not advised")
        self.mode = mode

    def __enter__(self):
        """Open the binary file context with context."""
        self.file = open(self.file_path, self.mode)
        # Cache file size for bounds checking
        current_pos = self.file.tell()
        self.file.seek(0, os.SEEK_END)
        self._size = self.file.tell()
        self.file.seek(current_pos)
        return self

    def __exit__(self, *args):
        """Close file on exit."""
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
        instance = cls.__new__(cls)
        instance.file_path = None
        instance.file = BytesIO(data)
        instance.mode = "rb"
        instance._size = len(data)
        return instance
