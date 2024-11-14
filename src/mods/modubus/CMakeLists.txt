file(GLOB SRC_SOURCES "*.c")

add_library(modubus STATIC ${SRC_SOURCES})
target_link_libraries(modubus ubus ubox hashmapc parson)
target_include_directories(modubus PUBLIC modubus)
