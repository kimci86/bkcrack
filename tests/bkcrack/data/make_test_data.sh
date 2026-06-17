#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"

rm -f *.zip

echo | zip empty.zip -
zip -d empty.zip -

echo store\ {A..Z} > store.txt
echo deflate\ {A..Z} > deflate.txt

zip -X -Z store   plain.zip store.txt
zip -X -Z deflate plain.zip deflate.txt

zip -X -Z store   -e -P password zipcrypto.zip store.txt
zip -X -Z deflate -e -P password zipcrypto.zip deflate.txt

zip -X -Z store   --force-zip64 zip64.zip store.txt
zip -X -Z deflate --force-zip64 zip64.zip deflate.txt

zip -X -Z store   -e -P password --force-zip64 zip64-zipcrypto.zip store.txt
zip -X -Z deflate -e -P password --force-zip64 zip64-zipcrypto.zip deflate.txt

7z a -mm=store   -mem=aes256 -ppassword aes256.zip store.txt
7z a -mm=deflate -mem=aes256 -ppassword aes256.zip deflate.txt

rm store.txt deflate.txt
