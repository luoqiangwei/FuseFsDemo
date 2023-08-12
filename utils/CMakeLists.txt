include_directories(include)
aux_source_directory(. UTILS_SRC)

add_library(utils ${UTILS_SRC})
