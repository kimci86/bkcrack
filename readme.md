bkcrack
=======

[![CI badge](https://github.com/kimci86/bkcrack/actions/workflows/ci.yml/badge.svg)](https://github.com/kimci86/bkcrack/actions/workflows/ci.yml)
[![release badge](https://img.shields.io/github/v/release/kimci86/bkcrack)](https://github.com/kimci86/bkcrack/releases)

Crack legacy zip encryption with Biham and Kocher's known plaintext attack.

Install
-------

### Precompiled packages

You can get the latest official release on [GitHub](https://github.com/kimci86/bkcrack/releases).

Precompiled packages for Ubuntu, MacOS and Windows are available for download.
Extract the downloaded archive wherever you like.

### Compile from source

Alternatively, you can compile the project with [CMake](https://cmake.org).

First, download the source files or clone the git repository.
Then, running the following commands in the source tree will create an installation in the `install` folder.

```
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=install
cmake --build build --config Release
cmake --build build --config Release --target install
```

### Arch Linux (unofficial)

An unofficial package [bkcrack-git](https://aur.archlinux.org/packages/bkcrack-git/) is available in AUR.

Install it with any AUR helpers you like.

Usage
-----

### Recover internal keys

The attack requires at least 12 bytes of known plaintext.
At least 8 of them must be contiguous.
The larger the contiguous known plaintext, the faster the attack.

#### Load data from zip archives

Having a zip archive `encrypted.zip` with the entry `cipher` being the ciphertext and `plain.zip` with the entry `plain` as the known plaintext, bkcrack can be run like this:

    bkcrack -C encrypted.zip -c cipher -P plain.zip -p plain

#### Load data from files

Having a file `cipherfile` with the ciphertext (starting with the 12 bytes corresponding to the encryption header) and `plainfile` with the known plaintext, bkcrack can be run like this:

    bkcrack -c cipherfile -p plainfile

#### Offset

If the plaintext corresponds to a part other than the beginning of the ciphertext, you can specify an offset.
It can be negative if the plaintext includes a part of the encryption header.

    bkcrack -c cipherfile -p plainfile -o offset

#### Sparse plaintext

If you know little contiguous plaintext (between 8 and 11 bytes), but know some bytes at some other known offsets, you can provide this information to reach the requirement of a total of 12 known bytes.
To do so, use the `-x` flag followed by an offset and bytes in hexadecimal.

    bkcrack -c cipherfile -p plainfile -x 25 4b4f -x 30 21

#### Number of threads

If bkcrack was built with parallel mode enabled, the number of threads used can be set through the environment variable `OMP_NUM_THREADS`.

### Decipher

If the attack is successful, the deciphered data associated to the ciphertext used for the attack can be saved:

    bkcrack -c cipherfile -p plainfile -d decipheredfile

If the keys are known from a previous attack, it is possible to use bkcrack to decipher data:

    bkcrack -c cipherfile -k 12345678 23456789 34567890 -d decipheredfile

#### Decompress

The deciphered data might be compressed depending on whether compression was used or not when the zip file was created.
If deflate compression was used, a Python 3 script provided in the `tools` folder may be used to decompress data.

    python3 tools/inflate.py < decipheredfile > decompressedfile

### Unlock encrypted archive

It is also possible to generate a new encrypted archive with the password of your choice:

    bkcrack -C encrypted.zip -k 12345678 23456789 34567890 -U unlocked.zip password

The archive generated this way can be extracted using any zip file utility with the new password.
It assumes that every entry was originally encrypted with the same password.

### Recover password

Given the internal keys, bkcrack can try to find the original password up to a given length:

    bkcrack -k 1ded830c 24454157 7213b8c5 -r 10 ?p

Learn
-----

A tutorial is provided in the `example` folder.

For more information, have a look at the documentation and read the source.

Contribute
----------

Do not hesitate to suggest improvements or submit pull requests on [GitHub](https://github.com/kimci86/bkcrack).

License
-------

This project is provided under the terms of the [zlib/png license](http://opensource.org/licenses/Zlib).
