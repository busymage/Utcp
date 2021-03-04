#include <Protocol/PacketBuilder.hpp>
#include <Protocol/ChecksumCalc.hpp>
#include <netinet/ip.h>
#include <string.h>

struct PacketBuilder::Impl
{
    std::vector<uint8_t> pkt;
};

PacketBuilder::PacketBuilder(uint32_t saddr,
                            uint32_t daddr,
                            const void *segment,
                            uint16_t len)
:impl_(new Impl)
{
    impl_->pkt.reserve(sizeof(iphdr) + len);
    iphdr ih = {0};
    ih.version = 4;
    ih.ihl = 5;
    ih.id = 0;
    ih.frag_off = 0;
    ih.ttl = 64;
    ih.protocol = 0x06;
    ih.saddr = saddr;
    ih.daddr = daddr;
    ih.tot_len = htons(40);
    ih.check = checksum(&ih, sizeof(iphdr), 0);

    uint8_t *ihStart = (uint8_t*)&ih;
    uint8_t *ihEnd = ihStart + sizeof(iphdr);
    impl_->pkt.insert(impl_->pkt.end(), ihStart, ihEnd);

    uint8_t *seg = (uint8_t*)segment;
    impl_->pkt.insert(impl_->pkt.end(), seg, seg + len);
}

PacketBuilder::~PacketBuilder() = default;

std::vector<uint8_t> &PacketBuilder::packet()
{
    return impl_->pkt;
}
