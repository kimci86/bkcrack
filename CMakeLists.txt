cmake_minimum_required(VERSION 3.16)

# project definition
project(bkcrack
    VERSION 1.6.0 # remember to update bkcrack_VERSION_DATE below when releasing a new version
    DESCRIPTION "Crack legacy zip encryption with Biham and Kocher's known plaintext attack."
    HOMEPAGE_URL "https://github.com/kimci86/bkcrack"
    LANGUAGES CXX)
set(bkcrack_VERSION_DATE "2024-01-02")

# default build type
set(default_build_type "Release")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
    set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# main program
add_subdirectory(src)

# documentation generation
option(BKCRACK_BUILD_DOC "Enable documentation generation with doxygen." OFF)
if(BKCRACK_BUILD_DOC)
    add_subdirectory(doc)
endif()

# automated tests
option(BKCRACK_BUILD_TESTING "Enable automated testing with ctest." OFF)
if(BKCRACK_BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
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
