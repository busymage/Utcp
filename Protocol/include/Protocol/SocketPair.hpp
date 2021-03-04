#ifndef UTCP_SOCKETPAIR_HPP
#define UTCP_SOCKETPAIR_HPP

#include <stdint.h>

struct SocketPair{
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
};

inline bool operator<(const SocketPair &lhs, const SocketPair &rhs)
{
    return lhs.dport < rhs.dport;
}

#endif