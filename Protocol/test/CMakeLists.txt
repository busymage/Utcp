cmake_minimum_required(VERSION 3.13.0)

find_package(GTest REQUIRED)

set(Sources src/TcpTest.cpp)

add_executable(TcpTest src/TcpTest.cpp)
add_executable(PacketBuilderTest src/PacketBuilderTest.cpp)
add_executable(PassiveSockTest src/PassiveSockTest.cpp)

target_link_libraries(TcpTest PUBLIC
    GTest::GTest
    GTest::Main
    Protocol)

target_link_libraries(PacketBuilderTest PUBLIC
    GTest::GTest
    GTest::Main
    Protocol)

target_link_libraries(PassiveSockTest PUBLIC
    GTest::GTest
    GTest::Main
    Protocol)

add_test(
    NAME TcpTest
    COMMAND TcpTest)

add_test(
    NAME PacketBuilderTest
    COMMAND PacketBuilderTest)

add_test(
    NAME PassiveSockTest
    COMMAND PassiveSockTest)