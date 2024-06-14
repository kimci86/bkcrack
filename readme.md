bkcrack
=======

[![CI badge](https://github.com/kimci86/bkcrack/actions/workflows/ci.yml/badge.svg)](https://github.com/kimci86/bkcrack/actions/workflows/ci.yml)
[![release badge](https://img.shields.io/github/v/release/kimci86/bkcrack)](https://github.com/kimci86/bkcrack/releases)
[![license badge](https://img.shields.io/github/license/kimci86/bkcrack?color=informational)](license.txt)
[![GitHub Sponsors badge](https://img.shields.io/github/sponsors/kimci86?color=red)](https://github.com/sponsors/kimci86)

Crack legacy zip encryption with Biham and Kocher's known plaintext attack.

Overview
--------

A ZIP archive may contain many entries whose content can be compressed and/or encrypted.
In particular, entries can be encrypted with a password-based symmetric encryption algorithm referred to as traditional PKWARE encryption, legacy encryption or ZipCrypto.
This algorithm generates a pseudo-random stream of bytes (keystream) which is XORed to the entry's content (plaintext) to produce encrypted data (ciphertext).
The generator's state, made of three 32-bits integers, is initialized using the password and then continuously updated with plaintext as encryption goes on.
This encryption algorithm is vulnerable to known plaintext attacks as shown by Eli Biham and Paul C. Kocher in the research paper [A known plaintext attack on the PKZIP stream cipher](https://doi.org/10.1007/3-540-60590-8_12).
Given ciphertext and 12 or more bytes of the corresponding plaintext, the internal state of the keystream generator can be recovered.
This internal state is enough to decipher ciphertext entirely as well as other entries which were encrypted with the same password.
It can also be used to bruteforce the password with a complexity of *n<sup>l-6</sup>* where *n* is the size of the character set and *l* is the length of the password.

**bkcrack** is a command-line tool which implements this known plaintext attack.
The main features are:

- Recover internal state from ciphertext and plaintext.
- Remove or change a ZIP archive's password using the internal state.
- Recover the original password from the internal state.

Install
-------

### Precompiled packages

You can get the latest official release on [GitHub](https://github.com/kimci86/bkcrack/releases).

Precompiled packages for Ubuntu, MacOS and Windows are available for download.
Extract the downloaded archive wherever you like.

On Windows, Microsoft runtime libraries are needed for bkcrack to run.
If they are not already installed on your system, download and install the latest Microsoft Visual C++ Redistributable package.

### Compile from source

Alternatively, you can compile the project with [CMake](https://cmake.org).

First, download the source files or clone the git repository.
Then, running the following commands in the source tree will create an installation in the `install` folder.

```
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=install
cmake --build build --config Release
cmake --build build --config Release --target install
```

### Third-party packages

bkcrack is available in the package repositories listed below.
Those packages are provided by external maintainers.

[![Packaging status](https://repology.org/badge/vertical-allrepos/bkcrack.svg)](https://repology.org/project/bkcrack/versions)

Usage
-----

### List entries

You can see a list of entry names and metadata in an archive named `archive.zip` like this:

    bkcrack -L archive.zip

Entries using ZipCrypto encryption are vulnerable to a known-plaintext attack.

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

### Decipher

If the attack is successful, the deciphered data associated to the ciphertext used for the attack can be saved:

    bkcrack -c cipherfile -p plainfile -d decipheredfile

If the keys are known from a previous attack, it is possible to use bkcrack to decipher data:

    bkcrack -c cipherfile -k 12345678 23456789 34567890 -d decipheredfile

#### Decompress

The deciphered data might be compressed depending on whether compression was used or not when the zip file was created.
If deflate compression was used, a Python 3 script provided in the `tools` folder may be used to decompress data.

    python3 tools/inflate.py < decipheredfile > decompressedfile

### Remove password

To get access to all the entries of the encrypted archive in a single step, you can generate a new archive with the same content but without encryption.
It assumes that every entry was originally encrypted with the same password.

    bkcrack -C encrypted.zip -k 12345678 23456789 34567890 -D decrypted.zip

### Change password

It is also possible to generate a new encrypted archive with the password of your choice:

    bkcrack -C encrypted.zip -k 12345678 23456789 34567890 -U unlocked.zip new_password

You can also define the new password by its corresponding internal representation.

    bkcrack -C encrypted.zip -k 12345678 23456789 34567890 --change-keys unlocked.zip 581da44e 8e40167f 50c009a0

Those two commands can be used together to change the contents of an encrypted archive without knowing the password but knowing only the internal keys:
you can make a copy encrypted with the password of you choice,
then edit the copy with an archive manager entering the chosen password when prompted,
and finally make a copy of the modified archive back with the original encryption keys.

### Recover password

Given the internal keys, bkcrack can try to find the original password.
You can look for a password up to a given length using a given character set:

    bkcrack -k 1ded830c 24454157 7213b8c5 -r 10 ?p

You can be more specific by specifying a minimal password length:

    bkcrack -k 18f285c6 881f2169 b35d661d -r 11..13 ?p

Learn
-----

A tutorial is provided in the `example` folder.

For more information, have a look at the documentation and read the source.

Contribute
----------

Do not hesitate to suggest improvements or submit pull requests on [GitHub](https://github.com/kimci86/bkcrack).

If you would like to show your support to the project, you are welcome to make a donation or sponsor the project via [Github Sponsors](https://github.com/sponsors/kimci86).

License
-------

This project is provided under the terms of the [zlib/png license](http://opensource.org/licenses/Zlib).
