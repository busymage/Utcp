#ifndef UTCP_PACKETBUILDER_HPP
#define UTCP_PACKETBUILDER_HPP

#include <memory>
#include <stdint.h>
#include <vector>

class PacketBuilder
{
private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
public:
    PacketBuilder(uint32_t saddr,
                uint32_t daddr,
                const void *segment,
                uint16_t len);
    ~PacketBuilder();

    std::vector<uint8_t> &packet();

    static uint32_t id;
};


#endif