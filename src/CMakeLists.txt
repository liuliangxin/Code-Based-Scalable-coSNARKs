aux_source_directory(. SRC)
include_directories(.)
add_executable(pigeon ${SRC})

target_link_libraries(pigeon pthread XKCP blake3 MPI::MPI_CXX)


