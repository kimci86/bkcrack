include(${PROJECT_SOURCE_DIR}/tests/verify_hash.cmake)

execute_process(
    COMMAND ${BKCRACK_COMMAND}
        -C ${PROJECT_SOURCE_DIR}/example/secrets.zip
        -k c4490e28 b414a23d 91404b31
        -D decrypt.zip
    COMMAND_ERROR_IS_FATAL ANY)
verify_hash(decrypt.zip 7365b22e535e545fc60952e82acea961dce512d939dd01545e0a20f7fe82bb8e)
file(REMOVE decrypt.zip)
