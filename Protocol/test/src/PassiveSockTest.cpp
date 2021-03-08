#include <gtest/gtest.h>
#include <Protocol/INetDevice.hpp>
#include <Protocol/PassiveSock.hpp>
#include <Protocol/Tcb.hpp>
#include <Protocol/Tcp.hpp>

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
    PassiveSock ps(tcp);
    ASSERT_FALSE(tcp->hasBoundPort(8888));
}

TEST_F(PassiveSockTest, bind)
{
    auto ps = std::make_shared<PassiveSock>(tcp);
    ps->bind(8888);
    ASSERT_TRUE(tcp->hasBoundPort(8888));
}

TEST_F(PassiveSockTest, close)
{
    auto ps = std::make_shared<PassiveSock>(tcp);
    ps->bind(8888);
    ps->close();
    ASSERT_FALSE(tcp->hasBoundPort(8888));
}

TEST_F(PassiveSockTest, acceptReturnNullWhileBacklogIsEmpty)
{
    auto ps = std::make_shared<PassiveSock>(tcp);
    ps->bind(8888);
    ASSERT_EQ(ps->accept(), nullptr);
    ps->close();
}