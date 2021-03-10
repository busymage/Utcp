cmake_minimum_required(VERSION 3.13.0)

set(Sources src/ChecksumCalc.cpp
            src/ConnectionSock.cpp
            src/PacketBuilder.cpp
            src/PassiveSock.cpp
            src/Segment.cpp
            src/Tcb.cpp
            src/Tcp.cpp
            src/TunNetDevice.cpp
            )

set(Headers include/Protocol/ChecksumCalc.hpp
            include/Protocol/ConnectionSock.hpp
            include/Protocol/INetDevice.hpp
            include/Protocol/ISock.hpp
            include/Protocol/PacketBuilder.hpp
            include/Protocol/PassiveSock.hpp
            include/Protocol/Segment.hpp
            include/Protocol/SocketPair.hpp
            include/Protocol/Tcp.hpp
            include/Protocol/Tcb.hpp
            include/Protocol/TunNetDevice.hpp
            )

add_library(Protocol ${Sources} ${Headers})

target_link_libraries(Protocol pthread)

include_directories(include)

add_subdirectory(test)
