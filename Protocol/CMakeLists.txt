cmake_minimum_required(VERSION 3.0.0)

set(Sources src/ChecksumCalc.cpp
            src/PacketBuilder.cpp
            src/Segment.cpp
            src/Tcp.cpp
            )

set(Headers include/Protocol/ChecksumCalc.hpp
            include/Protocol/PacketBuilder.hpp
            include/Protocol/Segment.hpp
            include/Protocol/SocketPair.hpp
            include/Protocol/Tcp.hpp
            include/Protocol/Tcb.hpp
            )

add_library(Protocol ${Sources} ${Headers})

include_directories(include)

#add_subdirectory(test)
