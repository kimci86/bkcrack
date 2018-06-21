#!/usr/bin/env python3

import sys
import zlib

def inflate(data):
    """Returns uncompressed data."""
    return zlib.decompress(data, -zlib.MAX_WBITS)

def main():
    """Read deflate compressed data from stdin and write uncompressed data to stdout."""
    sys.stdout.buffer.write(inflate(sys.stdin.buffer.read()))

if __name__ == "__main__":
    main()
