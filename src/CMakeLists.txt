file(GLOB SRC_SOURCES "*.c")

add_executable(jojodns ${SRC_SOURCES})

if(ENABLE_MOD_UBUS)
    add_definitions(-DMOD_UBUS)
    add_subdirectory(mods/modubus)
    target_link_libraries(jojodns modubus)
endif()

# Link the executable with libraries
target_link_libraries(jojodns ${LIBEVENT_LIBRARIES} hashmapc parson)
