# configure version header
string(TIMESTAMP TODAY "%Y-%m-%d")
set(VERSION_HEADER_CONFIGURED "${PROJECT_BINARY_DIR}/include/version.hpp" )
configure_file("${PROJECT_SOURCE_DIR}/include/version.hpp.in" "${VERSION_HEADER_CONFIGURED}")

# list files
file(GLOB HEADERS "${PROJECT_SOURCE_DIR}/include/*.hpp")
file(GLOB SOURCES "${PROJECT_SOURCE_DIR}/src/*.cpp")

# add the executable target
add_executable(${PROJECT_NAME} ${VERSION_HEADER_CONFIGURED} ${HEADERS} ${SOURCES})

# set include directories
target_include_directories(${PROJECT_NAME} PUBLIC
    "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_BINARY_DIR}/include"
    "${PROJECT_SOURCE_DIR}/external")

# enable C++11
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 11)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD_REQUIRED ON)

# enable OpenMP if wanted
if(BKCRACK_PARALLEL_MODE)
    find_package(OpenMP 2.0 REQUIRED)
    target_link_libraries(${PROJECT_NAME} PUBLIC OpenMP::OpenMP_CXX)
endif()

# install rules
install(TARGETS ${PROJECT_NAME} DESTINATION .)
