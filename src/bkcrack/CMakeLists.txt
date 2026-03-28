# configure version header
set(VERSION_HEADER_CONFIGURED "${PROJECT_BINARY_DIR}/include/bkcrack/version.hpp")
configure_file("${PROJECT_SOURCE_DIR}/include/bkcrack/version.hpp.in" "${VERSION_HEADER_CONFIGURED}")

# list files
file(GLOB HEADERS "${PROJECT_SOURCE_DIR}/include/bkcrack/*.hpp")
file(GLOB SOURCES "*.cpp")

# add the library target
add_library(bkcrack-core)
target_sources(bkcrack-core
    PUBLIC FILE_SET HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include ${PROJECT_BINARY_DIR}/include
    FILES
        ${VERSION_HEADER_CONFIGURED}
        ${HEADERS}
    PRIVATE
        ${SOURCES}
)
target_enable_warnings(bkcrack-core)

# enable C++20
target_compile_features(bkcrack-core PUBLIC cxx_std_20)

# let CMake work out the system-specific details to use threads
find_package(Threads REQUIRED)
target_link_libraries(bkcrack-core PRIVATE Threads::Threads)
