# find doxygen
find_package(Doxygen REQUIRED)

# set the input and output documentation paths
set(DOXYGEN_INPUT_DIR "${PROJECT_SOURCE_DIR}")
set(DOXYGEN_OUTPUT_DIR "${PROJECT_BINARY_DIR}/doc")

# configure the source doxyfile
set(DOXYGEN_CONFIGURED_INPUT "${DOXYGEN_OUTPUT_DIR}/doxyfile")
configure_file("${DOXYGEN_INPUT_DIR}/doc/doxyfile.in" "${DOXYGEN_CONFIGURED_INPUT}")

# list files
file(GLOB HEADERS "${PROJECT_SOURCE_DIR}/include/*.hpp")
file(GLOB DOCUMENTATION "${PROJECT_SOURCE_DIR}/doc/*.dox" "${PROJECT_SOURCE_DIR}/doc/*.md")

# add target
add_custom_target(doc ALL
    DEPENDS "${DOXYGEN_OUTPUT_DIR}/html/index.html"
    WORKING_DIRECTORY "${DOXYGEN_INPUT_DIR}")

add_custom_command(OUTPUT "${DOXYGEN_OUTPUT_DIR}/html/index.html"
    COMMAND "${DOXYGEN_EXECUTABLE}" "${DOXYGEN_CONFIGURED_INPUT}"
    DEPENDS ${DOCUMENTATION} ${HEADERS})

# install rules
install(DIRECTORY "${DOXYGEN_OUTPUT_DIR}/html" DESTINATION doc)
