cmake_minimum_required(VERSION 3.0.0)

set(Sources src/ChecksumCalc.cpp
            src/PacketBuilder.cpp
            src/Segment.cpp
            src/Tcb.cpp
            src/Tcp.cpp
            src/TunNetDevice.cpp
            )

set(Headers include/Protocol/ChecksumCalc.hpp
            include/Protocol/INetDevice.hpp
            include/Protocol/PacketBuilder.hpp
            include/Protocol/Segment.hpp
            include/Protocol/SocketPair.hpp
            include/Protocol/Tcp.hpp
            include/Protocol/Tcb.hpp
            include/Protocol/TunNetDevice.hpp
            )

add_library(Protocol ${Sources} ${Headers})

include_directories(include)

#add_subdirectory(test)
