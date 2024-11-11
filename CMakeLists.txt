cmake_minimum_required(VERSION 3.10)
project(JojoDNS C)

# Set the C standard
set(CMAKE_C_STANDARD 99)

# Set the compiler flags
set(CMAKE_C_FLAGS "-g -Wall -Wextra -Werror -pedantic -std=c99")

# Find libevent package using PkgConfig
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBEVENT REQUIRED libevent)

# Include directories for libevent
include_directories(${LIBEVENT_INCLUDE_DIRS} "include")


add_library(hashmapc STATIC lib/hashmapc/hashmap.c)

target_include_directories(hashmapc PUBLIC lib/hashmapc)

add_library(parson STATIC lib/parson/parson.c)

target_include_directories(parson PUBLIC lib/parson)

# Define the executable and list the source files
add_executable(jojodns
    src/main.c
    src/logging.c
    src/client.c
    src/server.c
    src/cache.c
    src/relay_forwarders.c
    src/relay_servers.c)

# Link the executable with libevent
target_link_libraries(jojodns ${LIBEVENT_LIBRARIES} hashmapc parson)


install(TARGETS jojodns
    RUNTIME DESTINATION bin
)
