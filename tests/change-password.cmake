include(${PROJECT_SOURCE_DIR}/tests/verify_hash.cmake)

execute_process(
    COMMAND ${BKCRACK_COMMAND}
        -C ${PROJECT_SOURCE_DIR}/example/secrets.zip
        -k c4490e28 b414a23d 91404b31
        -U change-password.zip new-password
    COMMAND_ERROR_IS_FATAL ANY)
verify_hash(change-password.zip 1aac8f747b205074ca662b533fa421f160b81d4f1afa99b750997d4038a49ebc)
file(REMOVE change-password.zip)
