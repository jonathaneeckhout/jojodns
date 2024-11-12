# Collect all .c files in the test directory
file(GLOB TEST_SOURCES "*.c")

# Collect all .c files in the src directory
file(GLOB SRC_SOURCES "../src/*.c")

list(REMOVE_ITEM SRC_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../src/main.c)

# Find CMocka
find_package(CMocka REQUIRED)
include_directories(${CMOCKA_INCLUDE_DIRS})

# Define the test executable
add_executable(jojodns_tests ${TEST_SOURCES} ${SRC_SOURCES})

# Include directories for tests
target_include_directories(jojodns_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include ${LIBEVENT_INCLUDE_DIRS})

# Link test executable with libraries
target_link_libraries(jojodns_tests ${CMOCKA_LIBRARIES} hashmapc parson ${LIBEVENT_LIBRARIES})

# Add a custom target to run tests
add_test(NAME JojoDNS_Tests COMMAND jojodns_tests)
