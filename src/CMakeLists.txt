aux_source_directory(. SRC)
aux_source_directory(accountability ACC_SRC)
include_directories(.)
add_executable(pigeon ${SRC} ${ACC_SRC})

target_link_libraries(pigeon pthread XKCP blake3 MPI::MPI_CXX OpenSSL::Crypto ${CMAKE_DL_LIBS})


