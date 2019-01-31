Tutorial {#tutorial}
========

\brief A guide to crack an example encrypted zip file.

The `example` folder contains an example zip file `secrets.zip` so you can run an attack.
Its content is probably of great interest!

# What is inside

Let us see what is inside.
Open a terminal in the `example` folder and ask `unzip` to give us information about it.

    $ unzip -Z secrets.zip

We get the following output.

    Archive:  secrets.zip
    Zip file size: 56263 bytes, number of entries: 2
    -rw-rw-r--  6.3 unx    54799 Bx defN 12-Aug-14 14:51 advice.jpg
    -rw-rw-r--  6.3 unx     1265 Bx stor 18-Dec-20 13:33 spiral.svg
    2 files, 56064 bytes uncompressed, 55953 bytes compressed:  0.2%

The zip file contains two files: `advice.jpg` and `spiral.svg`.
The capital letter in the fifth field shows the files are encrypted.
We also see that `advice.jpg` is deflated whereas `spiral.svg` is stored uncompressed.

# Guessing plaintext

To run the attack, we must guess at least 12 bytes of plaintext.
On average, the more plaintext we guess, the faster the attack will be.

## The easy way : stored file

We can guess from its extension that `spiral.svg` probably starts with the string `<?xml version="1.0" `.

We are so lucky that this file is stored uncompressed in the zip file.
So we have 20 bytes of plaintext, which is more than enough.

## The not so easy way : deflated file

Let us assume the zip file did not contain the uncompressed `spiral.svg`.

Then, to guess some plaintext, we can guess the first bytes of the original `advice.jpg` file from its extension.
The problem is that this file is compressed.
To run the attack, one would have to guess how those first bytes are compressed, which is difficult without knowing the entire file.

In this example, this approach is not practical.
It can be practical if the original file can easily be found online, like a .dll file for example.
Then, one would compress it using various compression software and compression levels to try and generate the correct plaintext.

## Free additional byte from CRC

In this example, we guessed the first 20 bytes of `spiral.svg`.

In addition, as explained in the ZIP file format specification, a 12-byte encryption header in prepended to the data in the archive.
The last byte of the encryption header is the most significant byte of the file's CRC.

We can get the CRC with `unzip`.

    $ unzip -Z -v secrets.zip spiral.svg | grep CRC
      32-bit CRC value (hex):                         a99f1d0d

So we know the byte just before the plaintext (i.e. at offset -1) is 0xA9.

# Running the attack

Let us write the plaintext we guessed in a file.

    $ echo -n -e '\xa9<?xml version="1.0" ' > plain.txt

We are now ready to run the attack.

    $ ../bkcrack -C secrets.zip -c spiral.svg -p plain.txt -o -1

After a little while, the keys will appear!

    Generated 4194304 Z values.
    [19:28:24] Z reduction using 9 extra bytes of known plaintext
    100.0 % (9 / 9)
    693762 values remaining.
    [19:28:26] Attack on 693762 Z values at index 10
    7.8 % (53913 / 693762)
    [19:31:02] Keys
    c4038591 d5ff449d d3b0c696

# Recovering the original files

Once we have the keys, we can decipher the files.
We assume that the same keys were used for all the files in the zip file.

    $ ../bkcrack -C secrets.zip -c spiral.svg -k c4038591 d5ff449d d3b0c696 -d spiral_deciphered.svg

The file `spiral.svg` was stored uncompressed so we are done.

    $ ../bkcrack -C secrets.zip -c advice.jpg -k c4038591 d5ff449d d3b0c696 -d advice_deciphered.deflate

The file `advice.jpg` was compressed with the deflate algorithm in the zip file, so we now have to uncompressed it.

A python script is provided for this purpose in the `tools` folder.

    $ ../tools/inflate.py < advice_deciphered.deflate > very_good_advice.jpg

You can now open `very_good_advice.jpg` and enjoy it!
