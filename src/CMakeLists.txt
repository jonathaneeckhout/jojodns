# Collect all .c files in the src directory
file(GLOB SRC_SOURCES "*.c")

# Define the executable
add_executable(jojodns ${SRC_SOURCES})

# Link the executable with libraries
target_link_libraries(jojodns ${LIBEVENT_LIBRARIES} hashmapc parson)
