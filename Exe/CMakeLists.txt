cmake_minimum_required(VERSION 3.0.0)

set(Sources src/tun.cpp)

add_executable(Utcp ${Sources})

include_directories(../Protocol/include)

target_link_libraries(Utcp Protocol)