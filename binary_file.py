"""
Define BinaryFile class.
"""


class BinaryFile:
    """Format for easily manipulation of binary files with pointers."""
    def __init__(self, file_path):
        self.file_path = file_path

    def __enter__(self):
        self.file = open(self.file_path, 'rb')
        return self

    def __exit__(self, *args):
        self.file.close()

    def read(self, num_bytes):
        return self.file.read(num_bytes)

    def read_int(self):
        return int.from_bytes(self.file.read(4), byteorder='little')

    def seek(self, offset, seek_type=0):
        self.file.seek(offset, seek_type)
