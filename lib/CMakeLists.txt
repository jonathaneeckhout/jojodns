add_library(hashmapc STATIC hashmapc/hashmap.c)
target_include_directories(hashmapc PUBLIC hashmapc)

add_library(parson STATIC parson/parson.c)
target_include_directories(parson PUBLIC parson)