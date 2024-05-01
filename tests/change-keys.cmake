include(${PROJECT_SOURCE_DIR}/tests/verify_hash.cmake)

execute_process(
    COMMAND ${BKCRACK_COMMAND}
        -C ${PROJECT_SOURCE_DIR}/example/secrets.zip
        -k c4490e28 b414a23d 91404b31
        --change-keys change-keys.zip 86484f1d 3fb4c16f ba11de5e
    COMMAND_ERROR_IS_FATAL ANY)
verify_hash(change-keys.zip 1aac8f747b205074ca662b533fa421f160b81d4f1afa99b750997d4038a49ebc)
file(REMOVE change-keys.zip)
