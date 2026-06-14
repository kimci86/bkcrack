# list files
file(GLOB HEADERS "*.hpp")
file(GLOB SOURCES "*.cpp")
list(FILTER SOURCES EXCLUDE REGEX "main\\.cpp")

# add the library target
add_library(bkcrack-cli)
target_sources(bkcrack-cli
    PUBLIC FILE_SET HEADERS
    FILES
        ${HEADERS}
    PRIVATE
        ${SOURCES}
)
target_enable_warnings(bkcrack-cli)
target_link_libraries(bkcrack-cli PUBLIC bkcrack-core)

# add the executable target
add_executable(bkcrack)
target_sources(bkcrack PRIVATE main.cpp utf-8.manifest)
target_enable_warnings(bkcrack)
target_link_libraries(bkcrack PRIVATE bkcrack-cli)
if(EMSCRIPTEN)
    target_link_options(bkcrack PRIVATE -sEXECUTABLE -sENVIRONMENT=node -sNODERAWFS)
endif()

# install rules
install(TARGETS bkcrack DESTINATION .)
if(EMSCRIPTEN)
    install(FILES $<TARGET_FILE_DIR:bkcrack>/bkcrack.wasm DESTINATION .)
endif()
