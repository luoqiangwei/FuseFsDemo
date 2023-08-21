CMAKE_MINIMUM_REQUIRED(VERSION 3.0)

project(ConfigFs)

set(CMAKE_C_COMPILER "/usr/bin/clang")
set(CMAKE_CXX_COMPILER "/usr/bin/clang++")
set(CMAKE_CXX_STANDARD 20)

set(enableFuse3 Y)
if(enableFuse3)
add_compile_options(-Wall -Wextra -Wpedantic -D_FILE_OFFSET_BITS=64 -DHAVE_FUSE3 -DFUSE_USE_VERSION=35 -DMOUNT_POINT="/tmp/configfs")
else()
add_compile_options(-Wall -Wextra -Wpedantic -D_FILE_OFFSET_BITS=64 -DHAVE_FUSE -DFUSE_USE_VERSION=26 -DMOUNT_POINT="/tmp/configfs")
endif()

add_subdirectory(utils)
add_subdirectory(configfs)

include_directories(utils/include)
include_directories(configfs/include)

aux_source_directory(. SRC)
add_executable(confs ${SRC})
target_link_libraries(confs configfs)
target_link_libraries(confs utils)
