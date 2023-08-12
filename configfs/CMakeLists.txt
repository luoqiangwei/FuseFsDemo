include_directories(include)
include_directories(../utils/include)
aux_source_directory(. CONFIGFS_DIR_SRC)

add_library(configfs ${CONFIGFS_DIR_SRC})
target_link_libraries(configfs fuse3)
# target_link_libraries(configfs fuse)
