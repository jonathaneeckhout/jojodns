file(GLOB SRC_SOURCES "*.c")

add_library(modubus STATIC ${SRC_SOURCES})
target_include_directories(modubus PUBLIC modubus)