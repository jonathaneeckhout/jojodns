cmake_minimum_required(VERSION 3.10)
project(JojoDNS C)

# Set the C standard
set(CMAKE_C_STANDARD 99)

# Set the compiler flags
set(CMAKE_C_FLAGS "-g -Wall -Wextra -Werror -pedantic -std=c99")

# Find libevent package using PkgConfig
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBEVENT REQUIRED libevent)

# Include directories for libevent and headers
include_directories(${LIBEVENT_INCLUDE_DIRS} "include")

# Add subdirectories
add_subdirectory(lib)
add_subdirectory(src)
add_subdirectory(test)

# Install the executable
install(TARGETS jojodns
    RUNTIME DESTINATION bin
)

# Enable testing
enable_testing()
