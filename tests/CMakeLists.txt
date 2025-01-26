add_test(NAME cli.attack
    COMMAND bkcrack -C secrets.zip -c spiral.svg -x 0 3c3f786d6c2076657273696f6e3d22312e302220 --continue-attack 183500
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/example)
set_tests_properties(cli.attack PROPERTIES PASS_REGULAR_EXPRESSION "
.* Z reduction using 13 bytes of known plaintext
.* Attack on 542303 Z values at index 6
.* Keys
c4490e28 b414a23d 91404b31
")

add_test(NAME cli.password COMMAND bkcrack --password W4sF0rgotten)
set_tests_properties(cli.password PROPERTIES PASS_REGULAR_EXPRESSION "c4490e28 b414a23d 91404b31")

add_test(NAME cli.decipher COMMAND ${CMAKE_COMMAND}
    -DBKCRACK_COMMAND=$<TARGET_FILE:bkcrack>
    -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
    -P ${CMAKE_CURRENT_SOURCE_DIR}/decipher.cmake)

add_test(NAME cli.decrypt COMMAND ${CMAKE_COMMAND}
    -DBKCRACK_COMMAND=$<TARGET_FILE:bkcrack>
    -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
    -P ${CMAKE_CURRENT_SOURCE_DIR}/decrypt.cmake)

add_test(NAME cli.change-password COMMAND ${CMAKE_COMMAND}
    -DBKCRACK_COMMAND=$<TARGET_FILE:bkcrack>
    -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
    -P ${CMAKE_CURRENT_SOURCE_DIR}/change-password.cmake)

add_test(NAME cli.change-keys COMMAND ${CMAKE_COMMAND}
    -DBKCRACK_COMMAND=$<TARGET_FILE:bkcrack>
    -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
    -P ${CMAKE_CURRENT_SOURCE_DIR}/change-keys.cmake)

add_test(NAME cli.bruteforce.empty  COMMAND bkcrack -k 12345678 23456789 34567890 -r 0 ?b)
add_test(NAME cli.bruteforce.tiny   COMMAND bkcrack -k 1b226dfe c089e0a3 6af00ee6 -r 4 ?b)
add_test(NAME cli.bruteforce.small  COMMAND bkcrack -k 9bcb20c6 10a97ca5 103c0614 -r 8 ?p)
add_test(NAME cli.bruteforce.medium COMMAND bkcrack -k edb43a00 9ce6e179 8cf2cbba -r 10 ?a)
add_test(NAME cli.bruteforce.long   COMMAND bkcrack -k dcce7593 b8a2e617 b2bd4365 -r 12 ?l)
set_tests_properties(cli.bruteforce.empty  PROPERTIES PASS_REGULAR_EXPRESSION "Password: \n")
set_tests_properties(cli.bruteforce.tiny   PROPERTIES PASS_REGULAR_EXPRESSION "Password: 🔐\n.*Password\nas bytes: f0 9f 94 90\nas text: 🔐\n")
set_tests_properties(cli.bruteforce.small  PROPERTIES PASS_REGULAR_EXPRESSION "Password: _S#cr3t!\n")
set_tests_properties(cli.bruteforce.medium PROPERTIES PASS_REGULAR_EXPRESSION "Password: q1w2e3r4t5\n")
set_tests_properties(cli.bruteforce.long   PROPERTIES PASS_REGULAR_EXPRESSION "Password: abcdefghijkl\n")

add_test(NAME cli.mask.empty COMMAND bkcrack -k 12345678 23456789 34567890 -m "")
add_test(NAME cli.mask.five  COMMAND bkcrack -k 5e07e483 0c4900a4 4e586ac1 -m ?u?l?d?s.)
add_test(NAME cli.mask.six   COMMAND bkcrack -k f9720e40 2520f2b9 0a5660df -m ?d?l?d?l?d?l)
add_test(NAME cli.mask.seven COMMAND bkcrack -k 2af9b027 85bd8154 286ca64f -m ?l?l?l?l?l?l?l)
add_test(NAME cli.mask.long  COMMAND bkcrack -k 0d892b8b 02dd8fad 77f52c7b -m ?l?l?l?l?l?l?l?l-?d?d?d?d)
set_tests_properties(cli.mask.empty PROPERTIES PASS_REGULAR_EXPRESSION "Password: \n")
set_tests_properties(cli.mask.five  PROPERTIES PASS_REGULAR_EXPRESSION "Password: Aa1_.\n")
set_tests_properties(cli.mask.six   PROPERTIES PASS_REGULAR_EXPRESSION "Password: 1q2w3e\n")
set_tests_properties(cli.mask.seven PROPERTIES PASS_REGULAR_EXPRESSION "Password: letmein\n")
set_tests_properties(cli.mask.long  PROPERTIES PASS_REGULAR_EXPRESSION "Password: password-1234\n")

add_test(NAME cli.mask.constant COMMAND bkcrack -k c80f5189 ce16bd43 38247eb5 -m "Lorem ipsum dolor sit amet")
add_test(NAME cli.mask.suffix   COMMAND bkcrack -k c80f5189 ce16bd43 38247eb5 -m "Lorem ipsum dolor ?1?1?1?1?1?1?1?1" -s 1 ?s?l)
add_test(NAME cli.mask.prefix   COMMAND bkcrack -k c80f5189 ce16bd43 38247eb5 -m "?u?1?1?1?1 ipsum dolor sit amet" -s 1 ?s?l)
add_test(NAME cli.mask.factor   COMMAND bkcrack -k c80f5189 ce16bd43 38247eb5 -m "Lorem ipsum ?1?1?1?1?1?1?1?1?1 amet" -s 1 ?s?l)
add_test(NAME cli.mask.sparse   COMMAND bkcrack -k c80f5189 ce16bd43 38247eb5 -m "Lo?le?l i?ls?lm do?lo?l sit a?let")
set_tests_properties(cli.mask.constant PROPERTIES PASS_REGULAR_EXPRESSION "Password: Lorem ipsum dolor sit amet\n")
set_tests_properties(cli.mask.suffix   PROPERTIES PASS_REGULAR_EXPRESSION "Password: Lorem ipsum dolor sit amet\n")
set_tests_properties(cli.mask.prefix   PROPERTIES PASS_REGULAR_EXPRESSION "Password: Lorem ipsum dolor sit amet\n")
set_tests_properties(cli.mask.factor   PROPERTIES PASS_REGULAR_EXPRESSION "Password: Lorem ipsum dolor sit amet\n")
set_tests_properties(cli.mask.sparse   PROPERTIES PASS_REGULAR_EXPRESSION "Password: Lorem ipsum dolor sit amet\n")

add_test(NAME cli.charset.one-letter    COMMAND bkcrack --password aaaaaa -r 6 ?0 -s 0 a)
add_test(NAME cli.charset.four-letters  COMMAND bkcrack --password abcabc -r 6 ?0 -s 0 abcd)
add_test(NAME cli.charset.hexadecimal   COMMAND bkcrack --password 1a2b3c -r 6 ?h -s h ?dabcdef)
add_test(NAME cli.charset.question-mark COMMAND bkcrack --password hello? -r 6 ?h -s h ?l?)

add_test(NAME cli.charset.short-cycle COMMAND bkcrack --password "" -r 0 ?0 -s 0 ?0)
add_test(NAME cli.charset.long-cycle  COMMAND bkcrack --password "" -r 0 ?0 -s 0 ?1 -s 1 ?2 -s 2 ?3 -s 3 ?4 -s 4 ?5 -s 5 ?0)
set_tests_properties(cli.charset.short-cycle PROPERTIES PASS_REGULAR_EXPRESSION "circular reference")
set_tests_properties(cli.charset.long-cycle  PROPERTIES PASS_REGULAR_EXPRESSION "circular reference")

add_test(NAME cli.list COMMAND bkcrack -L secrets.zip WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/example)
set_tests_properties(cli.list PROPERTIES PASS_REGULAR_EXPRESSION "
Index Encryption Compression CRC32    Uncompressed  Packed size Name
----- ---------- ----------- -------- ------------ ------------ ----------------
    0 ZipCrypto  Deflate     7ca9f10a        54799        54700 advice.jpg
    1 ZipCrypto  Store       a99f1d0d         1265         1277 spiral.svg
")

add_test(NAME cli.version COMMAND bkcrack --version)
set_tests_properties(cli.version PROPERTIES PASS_REGULAR_EXPRESSION "^bkcrack ${bkcrack_VERSION} - ${bkcrack_VERSION_DATE}\n\$")

add_test(NAME cli.help COMMAND bkcrack -h)
set_tests_properties(cli.help PROPERTIES PASS_REGULAR_EXPRESSION "usage:")
