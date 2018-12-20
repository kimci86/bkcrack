bkcrack
=======

Crack legacy zip encryption with Biham and Kocher's known plaintext attack.

Download
--------

Get the latest version from the [git repository](https://github.com/kimci86/bkcrack).

Install
-------

Build and install it with [CMake](https://cmake.org).

The following options can be configured:

- `CMAKE_INSTALL_PREFIX`: Install path prefix, prepended onto install directories.
- `CMAKE_BUILD_TYPE`: Type of build (Debug or Release).
- `PARALLEL_MODE`: Enable multithreaded attack with [OpenMP](http://openmp.org). This requires a compiler that supports OpenMP.
- `BUILD_DOC`: Enable documentation generation with [doxygen](http://doxygen.org).

Usage
-----

### Data required

The attack uses at least 12 bytes of contiguous plaintext.
The larger the known plaintext, the faster the attack.

#### From zip archives

Having a zip archive `encrypted.zip` with the entry `cipher` being the ciphertext and `plain.zip` with the entry `plain` as the known plaintext, bkcrack can be run like this:

    bkcrack -C encrypted.zip -c cipher -P plain.zip -p plain

#### From files

Having a file `cipherfile` with the ciphertext (starting with the 12 bytes corresponding to the encryption header) and `plainfile` with the known plaintext, bkcrack can be run like this:

    bkcrack -c cipherfile -p plainfile

#### Offset

If the plaintext corresponds to a part other than the beginning of the ciphertext, you can specify an offset.
It can be negative if the plaintext includes a part of the encryption header.

    bkcrack -c cipherfile -p plainfile -o offset

### Decipher

If the attack is successful, the deciphered text can be saved:

    bkcrack -c cipherfile -p plainfile -d decipheredfile

If the keys are known from a previous attack, it is possible to use bkcrack to decipher data:

    bkcrack -c cipherfile -k 12345678 23456789 34567890 -d decipheredfile

### Decompress

The deciphered data might be compressed depending on whether compression was used or not when the zip file was created.
If deflate compression was used, a Python 3 script provided in the `tools` folder may be used to decompress data.

    tools/inflate.py < decipheredfile > decompressedfile

### Number of threads

If bkcrack was built with parallel mode enabled, the number of threads used can be set through the environment variable `OMP_NUM_THREADS`.

Learn
-----

A tutorial is provided in the `example` folder.

For more information, have a look at the documentation and read the source.

Contribute
----------

Do not hesitate to suggest improvements or submit pull requests on [github](https://github.com/kimci86/bkcrack).

License
-------

This project is provided under the terms of the [zlib/png license](http://opensource.org/licenses/Zlib).
