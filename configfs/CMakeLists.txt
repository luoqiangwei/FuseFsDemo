include_directories(include)
include_directories(../utils/include)
aux_source_directory(. CONFIGFS_DIR_SRC)

add_library(configfs ${CONFIGFS_DIR_SRC})
if(enableFuse3)
target_link_libraries(configfs fuse3)
else()
target_link_libraries(configfs fuse)
endif()

