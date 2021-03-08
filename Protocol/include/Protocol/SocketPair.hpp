#ifndef UTCP_SOCKETPAIR_HPP
#define UTCP_SOCKETPAIR_HPP

#include <stdint.h>

struct SocketPair{
    uint32_t saddr;
    uint16_t sport;
    uint32_t daddr;
    uint16_t dport;
};

inline bool operator<(const SocketPair &lhs, const SocketPair &rhs)
{
    return lhs.dport < rhs.dport;
}

inline bool operator==(const SocketPair &lhs, const SocketPair &rhs)
{
    return  lhs.saddr == rhs.saddr &&
            lhs.sport == rhs.sport &&
            lhs.daddr == rhs.daddr &&
            lhs.dport == rhs.dport;
}

#endif