#!/usr/bin/env python3

import sys
import zlib
import argparse

parser = argparse.ArgumentParser(description='Deflate stdin to stdout')

parser.add_argument('--level',
                    metavar='LEVEL',
                    type=int,
                    choices=range(-1, 9 + 1),
                    help='Compression level (0..9 or -1 for default)',
                    default=-1)

parser.add_argument('--wsize',
                    metavar='WSIZE',
                    type=int,
                    choices=range(9, 15 + 1),
                    help='Window size (9..15)',
                    default=zlib.MAX_WBITS)

parser.add_argument('-z',
                    action='store_true',
                    help='Add zlib header to output')

args = parser.parse_args()

def deflate(data, level, wbits):
    """Returns compressed data."""
    z = zlib.compressobj(level, zlib.DEFLATED, wbits)
    data = z.compress(data)
    data += z.flush()
    return data

def main():
    """Read uncompressed data from stdin and write deflated data to stdout."""
    if args.z:
        wbits = args.wsize
    else:
        wbits = -args.wsize
    sys.stdout.buffer.write(deflate(sys.stdin.buffer.read(), args.level, wbits))

if __name__ == "__main__":
    main()
