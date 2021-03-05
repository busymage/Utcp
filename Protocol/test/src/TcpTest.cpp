#include <gtest/gtest.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <Protocol/INetDevice.hpp>
#include <Protocol/Tcb.hpp>
#include <Protocol/Tcp.hpp>
#include <Protocol/ChecksumCalc.hpp>
#include <Protocol/PacketBuilder.hpp>
#include <deque>
#include <string.h>

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

class TcpTest : public testing::Test
{
public:
    std::shared_ptr<MockNetDev> netDev;
    Tcp *tcp;
    SocketPair sp;

public:
    virtual void SetUp()
    {
        netDev = std::make_shared<MockNetDev>();
        tcp = new Tcp(netDev);
        netDev->tcp = tcp;
        tcp->addListener(9981);
        sp = {
            0xa000001,
            htons(999),
            0xa000002,
            htons(9981)
        };
    }

    virtual void TearDown()
    {
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
    tcphdr *hdr = (tcphdr *)(data.data() + sizeof(iphdr));
    ASSERT_EQ(hdr->seq, 1234);
    ASSERT_EQ(hdr->rst, 1);
}

TEST_F(TcpTest, recvSynInListen)
{
    tcphdr th = {0};
    th.source = htons(999);
    th.dest = htons(9981);
    th.th_off = 5;
    th.seq = htonl(0x4567);
    th.ack_seq = 1234;
    th.syn = 1;
    th.window = 1234;
    th.check = caclTcpChecksum(&th, 20, 0xa000001, 0xa000002);
    PacketBuilder pb(0xa000001, 0xa000002, &th, 20);
    std::vector<uint8_t> packet = pb.packet();
    netDev->recv(packet.data(), packet.size());

    ASSERT_EQ(netDev->outData.size(), 1);
    std::vector<uint8_t> data = netDev->outData[0];
    tcphdr *hdr = (tcphdr *)(data.data() + sizeof(iphdr));
    ASSERT_EQ(hdr->ack_seq, htonl(0x4568));
    ASSERT_EQ(hdr->syn, 1);
    ASSERT_EQ(hdr->ack, 1);

    std::shared_ptr<Tcb> tcb = tcp->getEstablishedConnection(sp);
    ASSERT_NE(tcb, nullptr);
    ASSERT_EQ(tcb->snd.iss, ntohl(hdr->seq));
    ASSERT_EQ(tcb->snd.nxt, tcb->snd.iss + 1);
    ASSERT_EQ(tcb->snd.iss, tcb->snd.una);
    ASSERT_EQ(tcb->snd.wnd, ntohs(th.window));

    ASSERT_EQ(tcb->rcv.irs, ntohl(th.seq));
    ASSERT_EQ(tcb->rcv.nxt, ntohl(th.seq) + 1);
    ASSERT_EQ(tcb->state, TcpState::SYN_RECEIVED);
}

TEST_F(TcpTest, notAcceptableSgementIncoming)
{
    std::shared_ptr<Tcb> tcb = std::make_shared<Tcb>(sp);
    tcb->state = TcpState::ESTABLISHED;
    tcb->snd.nxt = 0x1234;
    tcb->rcv.wnd = 0;
    tcb->rcv.nxt = 0x4567;
    ASSERT_TRUE(tcp->addConnection(tcb));
    ASSERT_TRUE(tcp->isEstablished(sp));

    tcphdr th = {0};
    th.source = sp.sport;
    th.dest = sp.dport;
    th.th_off = 5;
    th.seq = htonl(0x4567);
    th.ack_seq = 1234;
    th.ack = 1;
    th.window = 1234;
    uint8_t *payload = new uint8_t[26];
    uint8_t str[] = "hello";
    memcpy(payload, &th, 20);
    memcpy(payload + 20, str, 5);
    th.check = caclTcpChecksum(payload, 25, sp.saddr, sp.daddr);
    PacketBuilder pb(sp.saddr, sp.daddr, payload, 25);
    std::vector<uint8_t> packet = pb.packet();
    netDev->recv(packet.data(), packet.size());

    ASSERT_EQ(netDev->outData.size(), 1);
    std::vector<uint8_t> data = netDev->outData[0];
    tcphdr *hdr = (tcphdr *)(data.data() + sizeof(iphdr));
    ASSERT_EQ(hdr->seq, htonl(0x1234));
    ASSERT_EQ(hdr->ack_seq, htonl(0x4567));
    ASSERT_EQ(hdr->ack, 1);

    delete[] payload;
}

TEST_F(TcpTest, SegLenAndWndAreZeroAndSeqNumNotEqualRcvNext)
{
    //SEG.SEQ = RCV.NXT
    std::shared_ptr<Tcb> tcb = std::make_shared<Tcb>(sp);
    tcb->state = TcpState::ESTABLISHED;
    tcb->snd.nxt = 0x1234;
    tcb->rcv.wnd = 0;
    tcb->rcv.nxt = 0x4567;
    ASSERT_TRUE(tcp->addConnection(tcb));

    tcphdr th = {0};
    th.source = sp.sport;
    th.dest = sp.dport;
    th.th_off = 5;
    th.seq = htonl(0x1234);
    th.ack_seq = htonl(0x1234);
    th.ack = 1;
    th.window = 1234;
    th.check = caclTcpChecksum(&th, 20, sp.saddr, sp.daddr);
    PacketBuilder pb(sp.saddr, sp.daddr, &th, 20);
    std::vector<uint8_t> packet = pb.packet();
    netDev->recv(packet.data(), packet.size());

    ASSERT_EQ(netDev->outData.size(), 1);
    std::vector<uint8_t> data = netDev->outData[0];
    tcphdr *hdr = (tcphdr *)(data.data() + sizeof(iphdr));
    ASSERT_EQ(hdr->seq, htonl(0x1234));
    ASSERT_EQ(hdr->ack_seq, htonl(0x4567));
    ASSERT_EQ(hdr->ack, 1);
}

TEST_F(TcpTest, SegNumNotBetweenWnd)
{
    //RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    std::shared_ptr<Tcb> tcb = std::make_shared<Tcb>(sp);
    tcb->state = TcpState::ESTABLISHED;
    tcb->snd.nxt = 0x1234;
    tcb->rcv.wnd = 512;
    tcb->rcv.nxt = 0x4567;
    ASSERT_TRUE(tcp->addConnection(tcb));

    tcphdr th = {0};
    th.source = sp.sport;
    th.dest = sp.dport;
    th.th_off = 5;
    th.seq = htonl(0x7890);
    th.ack_seq = htonl(0x1234);
    th.ack = 1;
    th.window = 1234;
    th.check = caclTcpChecksum(&th, 20, sp.saddr, sp.daddr);
    PacketBuilder pb(sp.saddr, sp.daddr, &th, 20);
    std::vector<uint8_t> packet = pb.packet();
    netDev->recv(packet.data(), packet.size());

    ASSERT_EQ(netDev->outData.size(), 1);
    std::vector<uint8_t> data = netDev->outData[0];
    tcphdr *hdr = (tcphdr *)(data.data() + sizeof(iphdr));
    ASSERT_EQ(hdr->seq, htonl(0x1234));
    ASSERT_EQ(hdr->ack_seq, htonl(0x4567));
    ASSERT_EQ(hdr->ack, 1);
}