cmake_minimum_required(VERSION 3.0.0)

add_executable(Server src/server.cpp)
add_executable(Client src/client.cpp)

include_directories(../Protocol/include)

target_link_libraries(Server Protocol)
target_link_libraries(Client Protocol)