# find doxygen
find_package(Doxygen REQUIRED)

# doxygen configuration
set(DOXYGEN_STRIP_FROM_PATH "${PROJECT_SOURCE_DIR}/include")
set(DOXYGEN_STRIP_FROM_INC_PATH "${PROJECT_SOURCE_DIR}/include")
set(DOXYGEN_QUIET "YES")
set(DOXYGEN_SEARCHENGINE "NO")
set(DOXYGEN_ALIASES [[limitation=\xrefitem limitations \"Known limitations\" \"Known limitations\"]])

# add target
doxygen_add_docs(doc ALL
    "${PROJECT_SOURCE_DIR}/doc"
    "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/example"
    COMMENT "Generating HTML documentation with doxygen")

# install rules
install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/html" DESTINATION doc)
