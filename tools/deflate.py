#!/usr/bin/env python3

import sys
import zlib
import argparse

def deflate(data, level=-1, wbits=-zlib.MAX_WBITS, strategy=zlib.Z_DEFAULT_STRATEGY):
    """Returns compressed data."""
    compressor = zlib.compressobj(level, zlib.DEFLATED, wbits, zlib.DEF_MEM_LEVEL, strategy)
    return compressor.compress(data) + compressor.flush()

def main():
    """Read uncompressed data from stdin and write deflated data to stdout."""

    # Strategies are described in the documentation of the deflateInit2 function in zlib's manual.
    # See: https://www.zlib.net/manual.html#Advanced
    zlib_strategies = {
        'default':      zlib.Z_DEFAULT_STRATEGY,
        'filtered':     zlib.Z_FILTERED,
        'huffman_only': zlib.Z_HUFFMAN_ONLY,
        'rle':          zlib.Z_RLE,
        'fixed':        zlib.Z_FIXED
    }

    parser = argparse.ArgumentParser(description='Deflate stdin to stdout')

    parser.add_argument('-l', '--level',
                        metavar='LEVEL',
                        type=int,
                        choices=range(-1, 9 + 1),
                        help='Compression level (0..9 or -1 for default)',
                        default=-1)

    parser.add_argument('-w', '--wsize',
                        metavar='WSIZE',
                        type=int,
                        choices=range(9, 15 + 1),
                        help='Base-two logarithm of the window size (9..15)',
                        default=zlib.MAX_WBITS)

    parser.add_argument('-s', '--strategy',
                        metavar='STRATEGY',
                        choices=zlib_strategies.keys(),
                        help=f"""Strategy to tune the compression algorithm (choose from '{"', '".join(zlib_strategies)}')""",
                        default='default')

    parser.add_argument('-z', '--zlib',
                        action='store_true',
                        help='Add zlib header and trailer to output. '
                             'This option is available for the completeness of this script. '
                             'ZIP files use raw deflate, so do not enable this option '
                             'if you need compressed plaintext for bkcrack.')

    args = parser.parse_args()

    if args.zlib:
        wbits = args.wsize
    else:
        wbits = -args.wsize
    sys.stdout.buffer.write(deflate(sys.stdin.buffer.read(), args.level, wbits, zlib_strategies[args.strategy]))

if __name__ == "__main__":
    main()
