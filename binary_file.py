"""
Define BinaryFile class.
"""


class BinaryFile:
    """Format for easily manipulation of binary files with pointers."""

    def __init__(self, file_path):
        self.file_path = file_path
        self.file = None

    def __enter__(self):
        self.file = open(self.file_path, "rb")
        return self

    def __exit__(self, *args):
        """Close file on exit."""
        self.file.close()

    def read(self, num_bytes):
        """Read num_bytes bytes."""
        return self.file.read(num_bytes)

    def read_byte(self):
        """Read next 4 bytes as a byte."""
        return self.file.read(4)

    def read_int(self):
        """Read next 4 bytes as an integer."""
        return int.from_bytes(self.read_byte(), byteorder="little")

    def seek(self, offset, seek_type=0):
        """Go to seek point."""
        self.file.seek(offset, seek_type)

    def tell(self):
        """Tell current pointer position."""
        return self.file.tell()
