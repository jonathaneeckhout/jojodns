# Collect all .c files in the test directory
file(GLOB TEST_SOURCES "*.c")

# Collect all .c files in the src directory
file(GLOB SRC_SOURCES "../src/*.c")

# Exclude main.c from the src files
list(REMOVE_ITEM SRC_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../src/main.c)

# Find CMocka
find_package(CMocka REQUIRED)
include_directories(${CMOCKA_INCLUDE_DIRS})

# Enable code coverage flags for GCC or Clang
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage")
endif()

# Define the test executable
add_executable(jojodns_tests ${TEST_SOURCES} ${SRC_SOURCES})

# Include directories for tests
target_include_directories(jojodns_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include ${LIBEVENT_INCLUDE_DIRS})

# Link test executable with libraries
target_link_libraries(jojodns_tests ${CMOCKA_LIBRARIES} hashmapc parson ${LIBEVENT_LIBRARIES})

# Add a custom target to run tests
add_test(NAME JojoDNS_Tests COMMAND jojodns_tests)

# Add a custom target to collect code coverage after running tests
# This uses lcov to collect coverage data and generate a report
enable_testing()
add_custom_target(coverage
    COMMAND ${CMAKE_COMMAND} -E env "GCOV_PREFIX=${CMAKE_BINARY_DIR}/cov" "GCOV_PREFIX_STRIP=2" lcov --capture --directory . --output-file coverage.info
    COMMAND lcov --remove coverage.info '/test/*' --output-file coverage.info
    COMMAND lcov --list coverage.info
    COMMENT "Generating code coverage report"
)

# Make sure the coverage target is built after the tests
add_dependencies(coverage jojodns_tests)
