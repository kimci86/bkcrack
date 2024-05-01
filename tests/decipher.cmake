include(${PROJECT_SOURCE_DIR}/tests/verify_hash.cmake)

execute_process(
    COMMAND ${BKCRACK_COMMAND}
        -C ${PROJECT_SOURCE_DIR}/example/secrets.zip
        -c advice.jpg
        -k c4490e28 b414a23d 91404b31
        -d decipher.advice.deflate
    COMMAND_ERROR_IS_FATAL ANY)
verify_hash(decipher.advice.deflate de3b1050d1ce81bcebaa9ea2c2481f7466c47188ca6ae3e9509975e68fd834da)
file(REMOVE decipher.advice.deflate)
