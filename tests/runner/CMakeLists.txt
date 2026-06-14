add_library(bkcrack-testrunner)
target_sources(bkcrack-testrunner
    PUBLIC FILE_SET HEADERS
    FILES
        TestRunner.hpp
    PRIVATE
        TestRunner.cpp
        main.cpp
)
target_enable_warnings(bkcrack-testrunner)
target_compile_features(bkcrack-testrunner PUBLIC cxx_std_20)

if(EMSCRIPTEN)
    target_compile_options(bkcrack-testrunner PUBLIC -fexceptions -pthread)
    target_link_options(bkcrack-testrunner PUBLIC -fexceptions -pthread)
endif()

# function for unit test definition and registration
function(bkcrack_add_unittest file)
    cmake_path(GET file STEM stem)
    string(TOLOWER ${stem} name)
    add_executable(unittest-${name} ${file})
    target_enable_warnings(unittest-${name})
    target_link_libraries(unittest-${name} PRIVATE bkcrack-testrunner ${ARGN})
    if(EMSCRIPTEN)
        target_link_options(unittest-${name} PRIVATE -sEXECUTABLE -sENVIRONMENT=node -sNODERAWFS)
    endif()
    add_test(NAME unittest.${name} COMMAND unittest-${name})
endfunction()

# test the testing framework itself
bkcrack_add_unittest(TestRunner-pass.test.cpp)
bkcrack_add_unittest(TestRunner-fail.test.cpp)
set_property(TEST unittest.testrunner-fail PROPERTY WILL_FAIL ON)
