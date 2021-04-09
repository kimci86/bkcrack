cmake_minimum_required(VERSION 3.16)

# project definition
project(bkcrack
    VERSION 1.2.0
    DESCRIPTION "Crack legacy zip encryption with Biham and Kocher's known plaintext attack."
    HOMEPAGE_URL "https://github.com/kimci86/bkcrack"
    LANGUAGES CXX)

# default build type
set(default_build_type "Release")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
    set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# option to select parallel or serial attack
option(BKCRACK_PARALLEL_MODE "Enable multithreaded attack with OpenMP." ON)

# option for building the documentation
option(BKCRACK_BUILD_DOC "Enable documentation generation with doxygen." OFF)

# add the subdirectories
add_subdirectory(src)
if(BKCRACK_BUILD_DOC)
    add_subdirectory(doc)
endif()

# install rules
install(DIRECTORY example DESTINATION .)
install(DIRECTORY tools DESTINATION .)
install(FILES readme.md DESTINATION .)
install(FILES license.txt DESTINATION .)

# package generation
if(WIN32)
    set(CPACK_GENERATOR "ZIP")
else()
    set(CPACK_GENERATOR "TGZ")
endif()
include(CPack)
