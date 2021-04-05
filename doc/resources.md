Resources {#resources}
=========

\brief Related publications, online resources and tools.

\if not_doxygen

**Some commands below are for doxygen only.**
**They are not rendered when viewing the file on GitHub.**

\endif

# Research papers

- \anchor BK94 [A known plaintext attack on the PKZIP stream cipher](https://link.springer.com/content/pdf/10.1007/3-540-60590-8_12.pdf)

  Biham E., Kocher P.C. (1995) A known plaintext attack on the PKZIP stream cipher. In: Preneel B. (eds) Fast Software Encryption. FSE 1994. Lecture Notes in Computer Science, vol 1008. Springer, Berlin, Heidelberg.
  [DOI](https://doi.org/10.1007/3-540-60590-8_12)

  Describes a known plaintext attack on the PKZIP stream cipher.
  Requires 13 bytes of known plaintext: 8 for generating 2^38 candidates and 5 for filtering candidates.

  There are several parts:
  + Optionally, using additional contiguous known plaintext to reduce the number of candidates.
  + Finding the password internal representation.
  + Recovering the password.

  bkcrack is based on this paper.

- [ZIP Attacks with Reduced Known Plaintext](https://link.springer.com/content/pdf/10.1007/3-540-45473-X_10.pdf)

  Stay M. (2002) ZIP Attacks with Reduced Known Plaintext. In: Matsui M. (eds) Fast Software Encryption. FSE 2001. Lecture Notes in Computer Science, vol 2355. Springer, Berlin, Heidelberg.
  [DOI](https://doi.org/10.1007/3-540-45473-X_10)

  Reviews Biham and Kocher attack.
  Suggests a small improvement to require 12 bytes instead of 13 bytes (not throwing aways 6 known bits in Y7).
  Suggests using CRC-32 check bytes from several files as known plaintext.

  Then, it presents other approaches.
  One is using 4 bytes of known plaintext to generate 2^63 candidates.
  The other uses a weakness in a random number generator.

- An Improved Known Plaintext %Attack on PKZIP Encryption Algorithm

  Jeong K.C., Lee D.H., Han D. (2012) An Improved Known Plaintext %Attack on PKZIP Encryption Algorithm. In: Kim H. (eds) Information Security and Cryptology. ICISC 2011. Lecture Notes in Computer Science, vol 7259. Springer, Berlin, Heidelberg.
  [DOI](https://doi.org/10.1007/978-3-642-31912-9_16)

  About speeding up the attack using known plaintext from several files.
  It assumes the very first bytes are known.
  However, the very first encrypted bytes are from the encryption header which starts with 10 or 11 random bytes.
  So, it does not seem practical unless the pseudo-random number generator used to fill the encryption header is broken.

- \anchor Coray2019 [Improved Forensic Recovery of PKZIP Stream Cipher Passwords](https://www.scitepress.org/Papers/2019/73605/73605.pdf)

  Coray, S., Coisel, I., Sanchez, I. (2019). Improved Forensic Recovery of PKZIP Stream Cipher Passwords. In Proceedings of the 5th International Conference on Information Systems Security and Privacy - Volume 1: ICISSP, ISBN 978-989-758-359-9, pages 328-335.
  [DOI](https://doi.org/10.5220/0007360503280335)

  About finding the actual password, either using the internal keys or not. Does computations on the GPU with OpenCL.

  Implemented in \ref hashcat :
  + %Attack on the password without plaintext: https://github.com/hashcat/hashcat/pull/1962
  + Recovering the password from the internal keys: https://github.com/hashcat/hashcat/pull/2032

# Books

- Applied Cryptanalysis: Breaking Ciphers in the Real World

  Stamp, M., & Low, R. M. (2007). Applied cryptanalysis: breaking ciphers in the real world. John Wiley & Sons.

  Contains a chapter about stream ciphers.
  A section is dedicated to PKZIP encryption and \ref BK94 "Biham and Kocher attack".

  + [Editor's page](https://www.wiley.com/en-us/-p-9780470148778)
  + [Author's page](http://www.cs.sjsu.edu/~stamp/crypto/)
  + [Author's slides on PKZIP attack](http://www.cs.sjsu.edu/~stamp/crypto/PowerPoint_PDF/8_PKZIP.pdf)

# ZIP specification

- \anchor APPNOTE [APPNOTE.TXT - .ZIP File Format Specification](https://www.pkware.com/documents/casestudies/APPNOTE.TXT)

  Published by PKWARE, Inc. which developed the ZIP format.

- [RFC1951 - DEFLATE Compressed %Data Format Specification](http://www.ietf.org/rfc/rfc1951.txt)

  Deflate compression algorithm is often used in ZIP files.

- [Microsoft Docs - DosDateTimeToFileTime function](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-dosdatetimetofiletime)

  Microsoft documentation page describing the date and time format used in ZIP date and time fields.

# Tools

## Cracking internal keys

- [PkCrack](https://www.unix-ag.uni-kl.de/~conrad/krypto/pkcrack.html)

  Biham and Kocher attack implementation by Peter Conrad.

  License: Postcardware

- [Aloxaf/rbkcrack](https://github.com/Aloxaf/rbkcrack)

  A Rust rewrite of bkcrack by Aloxaf.
  Added ZIP64 support long before bkcrack.

  License: zlib

## Password recovery

- \anchor hashcat [hashcat](https://hashcat.net/)

  Password recovery tool. See \ref Coray2019.

  License: MIT

- [John the Ripper](https://www.openwall.com/john/)

  Password recovery tool.

  License: GNU General Public License v2.0 (Almost, see [LICENSE](https://github.com/openwall/john/blob/bleeding-jumbo/doc/LICENSE))

- [mferland/libzc](https://github.com/mferland/libzc)

  Tool and library for cracking legacy zip files by Marc Ferland.
  Implements bruteforce, dictionary and known plaintext attacks to recover the password.

  License: GNU General Public License v3.0

## Other tools

- [Aloxaf/p7zip](https://github.com/Aloxaf/p7zip)

  A patched p7zip by Aloxaf.
  Supports ZIP file extraction using the interal keys with the following syntax:

      7za e cipher.zip '-p[12345678_23456789_34567890]'

  License: GNU Lesser General Public License v2.1 + unRAR restriction

- [madler/infgen](https://github.com/madler/infgen/)

  Deflate disassembler to convert a deflate, zlib, or gzip stream into a readable form.

  Copyrighted (Mark Adler, all rights reserved)

- [hannob/zipeinfo](https://github.com/hannob/zipeinfo)

  Python script telling which encryption method is used in a ZIP file.

  License: CC0 / Public Domain
