#include <gtest/gtest.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <Protocol/INetDevice.hpp>
#include <Protocol/Tcp.hpp>
#include <Protocol/ChecksumCalc.hpp>
#include <Protocol/PacketBuilder.hpp>
#include <deque>

class MockNetDev : public INetDevice{
public:
    Tcp *tcp;
    
    //nic out data
    std::deque<std::vector<uint8_t>> outData;

    virtual int send(const uint8_t *data, size_t len) override
    {
       std::vector<uint8_t> buf(data, data + len);
       outData.push_back(buf);
        return len;
    }
    virtual int recv(uint8_t *data, size_t len) override
    {
        std::vector<uint8_t> buf(data, data + len);
        tcp->packetProcessing(buf);
        return len;
    }   
    ~MockNetDev() 
    {

    }
};

class TcpTest: public testing::Test
{
public:
    std::shared_ptr<MockNetDev> netDev;
    Tcp *tcp;

public:
    virtual void SetUp()
    {
        netDev = std::make_shared<MockNetDev>();
        tcp = new Tcp(netDev);
        netDev->tcp = tcp;
        tcp->addListener(9981);
    }

    virtual void TearDown(){
        delete tcp;
    }
};


TEST_F(TcpTest, recvRstInListen)
{
    tcphdr th = {0};
    th.source = htons(999);
    th.dest = htons(9981);
    th.th_off = 5;
    th.rst = 1;
    th.window = 1234;
    th.check = caclTcpChecksum(&th, 20, 0xa000001, 0xa000002);
    PacketBuilder pb(0xa000001, 0xa000002, &th, 20);
    std::vector<uint8_t> packet = pb.packet();
    netDev->recv(packet.data(), packet.size());

    ASSERT_EQ(netDev->outData.size(), 0);
}

TEST_F(TcpTest, recvAckInListen)
{
    tcphdr th = {0};
    th.source = htons(999);
    th.dest = htons(9981);
    th.th_off = 5;
    th.ack_seq = 1234;
    th.ack = 1;
    th.window = 1234;
    th.check = caclTcpChecksum(&th, 20, 0xa000001, 0xa000002);
    PacketBuilder pb(0xa000001, 0xa000002, &th, 20);
    std::vector<uint8_t> packet = pb.packet();
    netDev->recv(packet.data(), packet.size());

    ASSERT_EQ(netDev->outData.size(), 1);
    std::vector<uint8_t> data = netDev->outData[0];
    tcphdr *hdr = (tcphdr*)(data.data() + sizeof(iphdr));
    ASSERT_EQ(hdr->seq, 1234);
    ASSERT_EQ(hdr->rst, 1);
}