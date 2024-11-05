cmake_minimum_required(VERSION 3.10)
project(JojoDNS C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBEVENT REQUIRED libevent)

add_executable(jojodns jojodns.c)

target_include_directories(jojodns PRIVATE ${LIBEVENT_INCLUDE_DIRS})
target_link_libraries(jojodns ${LIBEVENT_LIBRARIES})
