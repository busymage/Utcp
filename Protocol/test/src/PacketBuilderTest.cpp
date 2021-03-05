#include <gtest/gtest.h>
#include <netinet/ip.h>
#include <Protocol/PacketBuilder.hpp>

TEST(PacketBullderTest, dataIsSame)
{
    uint8_t data[25] = {0};
    for(size_t i = 0; i < 25; ++i)
    {
        data[i] = i;
    }
    PacketBuilder pb(0xa000001,0xa000002,data,25);
    auto pkt = pb.packet();
    ASSERT_EQ(pkt.size(), 45);
    for(size_t i = 0; i < 25; ++i)
    {
        ASSERT_EQ(data[i], pkt[20 + i]);
    }
    iphdr *ih = (iphdr*)pkt.data();
    ASSERT_EQ(ih->tot_len, htons(45));
}