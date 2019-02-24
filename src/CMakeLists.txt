# enable OpenMP if wanted
if(BKCRACK_PARALLEL_MODE)
    find_package(OpenMP REQUIRED)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif()

# set include directories
include_directories("${PROJECT_SOURCE_DIR}/include")

# list files
file(GLOB HEADERS "${PROJECT_SOURCE_DIR}/include/*.hpp")
file(GLOB SOURCES "${PROJECT_SOURCE_DIR}/src/*.cpp")

# add the executable target
add_executable(${PROJECT_NAME} ${HEADERS} ${SOURCES})

# enable C++11
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 11)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD_REQUIRED ON)

# install rules
install(TARGETS ${PROJECT_NAME} DESTINATION .)
