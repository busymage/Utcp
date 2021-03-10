#include <gtest/gtest.h>
#include <Protocol/INetDevice.hpp>
#include <Protocol/ConnectionSock.hpp>
#include <Protocol/ChecksumCalc.hpp>
#include <Protocol/PacketBuilder.hpp>
#include <Protocol/Tcb.hpp>
#include <Protocol/Tcp.hpp>
#include <arpa/inet.h>
#include <deque>
#include <netinet/ip.h>

uint8_t *constructSegmentCarrieData(tcphdr *th, int datalen)
{
    uint8_t *payload = new uint8_t[th->doff * 4 + datalen];
    if(payload == nullptr){
        perror("new");
        exit(1);
    }
    uint8_t *data = payload + th->doff * 4;
    memcpy(payload, th, th->doff * 4);
    memset(data, 'x', datalen);
    return payload;
}

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

class ConnectionSockTest : public testing::Test
{
public:
    std::shared_ptr<MockNetDev> netDev;
    Tcp *tcp;

    SocketPair sockname;

public:
    virtual void SetUp()
    {
        netDev = std::make_shared<MockNetDev>();
        tcp = new Tcp(netDev);
        netDev->tcp = tcp;
        tcp->run();
        sockname = {
            0xa000001,
            htons(9981),
            0xa000002,
            htons(888)
        };
    }

    virtual void TearDown()
    {
        tcp->stop();
    }
};

TEST_F(ConnectionSockTest, construct)
{
    auto tcb = std::make_shared<Tcb>(sockname);
    auto ps = std::make_shared<ConnectionSock>(tcp, tcb);
    ASSERT_EQ(tcp->getEstablishedConnection(sockname), nullptr);
    tcp->addConnection(ps);
    ASSERT_NE(tcp->getEstablishedConnection(sockname), nullptr);
    ASSERT_EQ(tcp->getEstablishedConnection(sockname)->name(), ps->name());
}

TEST_F(ConnectionSockTest, close)
{
    auto tcb = std::make_shared<Tcb>(sockname);
    tcb->state = TcpState::ESTABLISHED;
    auto ps = std::make_shared<ConnectionSock>(tcp, tcb);
    tcp->addConnection(ps);
    ps->close();
    ASSERT_EQ(1, netDev->outData.size());
    ASSERT_EQ(TcpState::FIN_WAIT1, tcb->state);
    std::vector<uint8_t> data = netDev->outData[0];
    tcphdr *hdr = (tcphdr *)(data.data() + sizeof(iphdr));
    ASSERT_EQ(hdr->fin, 1);
    ASSERT_EQ(hdr->ack, 1);
}

TEST_F(ConnectionSockTest, closeInCloseWait)
{
    auto tcb = std::make_shared<Tcb>(sockname);
    tcb->state = TcpState::CLOSE_WAIT;
    auto ps = std::make_shared<ConnectionSock>(tcp, tcb);
    tcp->addConnection(ps);
    ps->close();
    ASSERT_EQ(1, netDev->outData.size());
    ASSERT_EQ(TcpState::LAST_ACK, tcb->state);
}

TEST_F(ConnectionSockTest, send)
{
    auto tcb = std::make_shared<Tcb>(sockname);
    tcb->state = TcpState::ESTABLISHED;
    tcb->snd.wnd = 1024;
    auto ps = std::make_shared<ConnectionSock>(tcp, tcb);
    tcp->addConnection(ps);
    std::vector<uint8_t> buffer(1000, 'x');
    ASSERT_EQ(1000, ps->send(buffer));
    ASSERT_EQ(2, netDev->outData.size());
    std::vector<uint8_t> data = netDev->outData[0];
    iphdr *ih = (iphdr*)data.data();
    ASSERT_EQ(ih->tot_len, htons(40 + 536));
    tcphdr *hdr = (tcphdr *)(data.data() + sizeof(iphdr));
    ASSERT_EQ(hdr->seq, 0);
    data = netDev->outData[1];
    hdr = (tcphdr *)(data.data() + sizeof(iphdr));
    ASSERT_EQ(hdr->seq, htonl(536));
    ASSERT_EQ(tcb->snd.una, 0);
}

TEST_F(ConnectionSockTest, sendMultipleTime)
{
    auto tcb = std::make_shared<Tcb>(sockname);
    tcb->state = TcpState::ESTABLISHED;
    tcb->snd.wnd = 50000;
    auto ps = std::make_shared<ConnectionSock>(tcp, tcb);
    tcp->addConnection(ps);
    std::vector<uint8_t> buffer(1000, 'x');
    ASSERT_EQ(1000, ps->send(buffer));
    ASSERT_EQ(1000, ps->send(buffer));
    
    ASSERT_EQ(4, netDev->outData.size());
    std::vector<uint8_t> data = netDev->outData[3];
    tcphdr *hdr = (tcphdr *)(data.data() + sizeof(iphdr));
    ASSERT_EQ(hdr->seq, htonl(1536));
    ASSERT_EQ(tcb->snd.una, 0);
}

TEST_F(ConnectionSockTest, recv)
{
    auto tcb = std::make_shared<Tcb>(sockname);
    tcb->snd.nxt = 0x1234;
    tcb->snd.una = 0x1233;
    tcb->rcv.wnd = 1024;
    tcb->rcv.nxt = 0x4567;
    tcb->snd.wnd = 1024;
    tcb->state = TcpState::ESTABLISHED;
    auto ps = std::make_shared<ConnectionSock>(tcp, tcb);
    tcp->addConnection(ps);
    
    tcphdr th = {0};
    th.source = sockname.dport;
    th.dest = sockname.sport;
    th.doff = 5;
    th.seq = htonl(0x4567);
    th.ack_seq = htonl(0x1234);
    th.ack = 1;
    th.window = 1234;
    uint8_t *payload = constructSegmentCarrieData(&th, 1000);
    th.check = caclTcpChecksum(&th, 1020, sockname.daddr, sockname.saddr);
    PacketBuilder pb(sockname.daddr, sockname.saddr, &th, 1020);
    std::vector<uint8_t> packet = pb.packet();
    netDev->recv(packet.data(), packet.size());

    //second data
    th.seq = htonl(0x4567 + 1000);
    th.check = caclTcpChecksum(&th, 1020, sockname.daddr, sockname.saddr);
    PacketBuilder pb1(sockname.daddr, sockname.saddr, &th, 1020);
    std::vector<uint8_t> packet1 = pb1.packet();
    netDev->recv(packet1.data(), packet1.size());

    std::vector<uint8_t> buffer;
    ASSERT_EQ(ps->recv(buffer), 1024);
    ASSERT_EQ(tcb->rcv.wnd, 1024);
}

TEST_F(ConnectionSockTest, recvWhenPeerClose)
{
    auto tcb = std::make_shared<Tcb>(sockname);
    tcb->snd.nxt = 0x1234;
    tcb->snd.una = 0x1233;
    tcb->rcv.wnd = 1024;
    tcb->rcv.nxt = 0x4567;
    tcb->snd.wnd = 1024;
    tcb->state = TcpState::ESTABLISHED;
    auto ps = std::make_shared<ConnectionSock>(tcp, tcb);
    tcp->addConnection(ps);

    tcphdr th = {0};
    th.source = sockname.dport;
    th.dest = sockname.sport;
    th.doff = 5;
    th.seq = htonl(0x4567);
    th.ack_seq = htonl(0x1234);
    th.ack = 1;
    th.fin = 1;
    th.window = 1234;
    th.check = caclTcpChecksum(&th, 20, sockname.daddr, sockname.saddr);
    PacketBuilder pb(sockname.daddr, sockname.saddr, &th, 20);
    std::vector<uint8_t> packet = pb.packet();
    netDev->recv(packet.data(), packet.size());

    ASSERT_EQ(tcb->state, TcpState::CLOSE_WAIT);
    std::vector<uint8_t> buffer;
    ASSERT_EQ(ps->recv(buffer), 0);
}