cmake_minimum_required(VERSION 3.5)

# set project name and language
project(bkcrack CXX)

# default build type
set(CMAKE_BUILD_TYPE Release CACHE STRING "Type of build (Debug or Release)." FORCE)

# option to select parallel or serial attack
option(PARALLEL_MODE "Enable multithreaded attack with OpenMP." ON)

# option for building the documentation
option(BUILD_DOC "Enable documentation generation with doxygen." ON)

# add the subdirectories
add_subdirectory(src)
if(BUILD_DOC)
    add_subdirectory(doc)
endif()

# install rules
install(DIRECTORY example DESTINATION .)
install(FILES readme.md DESTINATION .)
install(FILES license.txt DESTINATION .)
