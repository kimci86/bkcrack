cmake_minimum_required(VERSION 3.0)

# set project name and language
project(bkcrack CXX)

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
