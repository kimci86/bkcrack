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

add_test(NAME cli.bruteforce.empty  COMMAND bkcrack -k 12345678 23456789 34567890 -r 0 ?b)
add_test(NAME cli.bruteforce.tiny   COMMAND bkcrack -k 1b226dfe c089e0a3 6af00ee6 -r 4 ?b)
add_test(NAME cli.bruteforce.small  COMMAND bkcrack -k 9bcb20c6 10a97ca5 103c0614 -r 8 ?p)
add_test(NAME cli.bruteforce.medium COMMAND bkcrack -k edb43a00 9ce6e179 8cf2cbba -r 10 ?a)
add_test(NAME cli.bruteforce.long   COMMAND bkcrack -k dcce7593 b8a2e617 b2bd4365 -r 12 ?l)
set_tests_properties(cli.bruteforce.empty  PROPERTIES PASS_REGULAR_EXPRESSION "Password: \n")
set_tests_properties(cli.bruteforce.tiny   PROPERTIES PASS_REGULAR_EXPRESSION "Password: 🔐\n")
set_tests_properties(cli.bruteforce.small  PROPERTIES PASS_REGULAR_EXPRESSION "Password: _S#cr3t!\n")
set_tests_properties(cli.bruteforce.medium PROPERTIES PASS_REGULAR_EXPRESSION "Password: q1w2e3r4t5\n")
set_tests_properties(cli.bruteforce.long   PROPERTIES PASS_REGULAR_EXPRESSION "Password: abcdefghijkl\n")

add_test(NAME cli.list COMMAND bkcrack -L secrets.zip WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/example)
set_tests_properties(cli.list PROPERTIES PASS_REGULAR_EXPRESSION "advice\.jpg.*spiral\.svg")

add_test(NAME cli.version COMMAND bkcrack --version)
set_tests_properties(cli.version PROPERTIES PASS_REGULAR_EXPRESSION "^bkcrack ${bkcrack_VERSION} - ${bkcrack_VERSION_DATE}\n\$")

add_test(NAME cli.help COMMAND bkcrack -h)
set_tests_properties(cli.help PROPERTIES PASS_REGULAR_EXPRESSION "usage:")
