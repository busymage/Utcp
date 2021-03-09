#include <gtest/gtest.h>
#include <Protocol/INetDevice.hpp>
#include <Protocol/ChecksumCalc.hpp>
#include <Protocol/PassiveSock.hpp>
#include <Protocol/PacketBuilder.hpp>
#include <Protocol/Tcb.hpp>
#include <Protocol/Tcp.hpp>
#include <arpa/inet.h>
#include <deque>

class MockNetDev : public INetDevice
{
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

class PassiveSockTest : public testing::Test
{
public:
    std::shared_ptr<MockNetDev> netDev;
    std::shared_ptr<Tcp> tcp;

public:
    virtual void SetUp()
    {
        netDev = std::make_shared<MockNetDev>();
        tcp = std::make_shared< Tcp >(netDev);
        netDev->tcp = tcp.get();
        tcp->run();
    }

    virtual void TearDown()
    {
        tcp->stop();
    }
};

TEST_F(PassiveSockTest, construct)
{
    auto ps = std::make_shared<PassiveSock>(tcp.get());
    ASSERT_FALSE(tcp->hasBoundPort(8888));
}

TEST_F(PassiveSockTest, bind)
{
    auto ps = std::make_shared<PassiveSock>(tcp.get());
    ps->bind(8888);
    ASSERT_TRUE(tcp->hasBoundPort(8888));
    auto tcb = ps->tcb();
    ASSERT_EQ(tcb->state, TcpState::LISTEN);
}

TEST_F(PassiveSockTest, close)
{
    auto ps = std::make_shared<PassiveSock>(tcp.get());
    ps->bind(8888);
    ps->close();
    ASSERT_FALSE(tcp->hasBoundPort(8888));
}

/*
TEST_F(PassiveSockTest, acceptReturnNullWhileBacklogIsEmpty)
{
    auto ps = std::make_shared<PassiveSock>(tcp.get());
    ps->bind(8888);
    ASSERT_EQ(ps->accept(), nullptr);
    ps->close();
}*/

TEST_F(PassiveSockTest, acceptConnection)
{
    auto ps = std::make_shared<PassiveSock>(tcp.get());
    ps->bind(8888);

    //inital handshake
    tcphdr th = {0};
    th.source = htons(999);
    th.dest = htons(8888);
    th.th_off = 5;
    th.seq = htonl(0x4567);
    th.ack_seq = 1234;
    th.syn = 1;
    th.window = 1234;
    th.check = caclTcpChecksum(&th, 20, 0xa000001, 0xa000002);
    PacketBuilder pb(0xa000001, 0xa000002, &th, 20);
    std::vector<uint8_t> packet = pb.packet();
    netDev->recv(packet.data(), packet.size());

    th.seq = htonl(0x4567 + 1);
    th.ack_seq = htonl(1);
    th.syn = 0;
    th.ack = 1;
    th.check = caclTcpChecksum(&th, 20, 0xa000001, 0xa000002);
    PacketBuilder pb1(0xa000001, 0xa000002, &th, 20);
    packet = pb1.packet();
    netDev->recv(packet.data(), packet.size());

    ASSERT_EQ(1, ps->waitingAcceptCount());
    auto sock = ps->accept();
    ASSERT_NE(sock, nullptr);
    ASSERT_EQ(0, ps->waitingAcceptCount());
}