#ifndef UTCP_TCP_HPP
#define UTCP_TCP_HPP

#include <future>
#include <memory>
#include <Protocol/SocketPair.hpp>
#include <vector>

class INetDevice;
class PassiveSock;
struct Tcb;

class Tcp
{
public:
    Tcp(std::shared_ptr<INetDevice> netDev);
    ~Tcp();

    bool isEstablished(SocketPair &pair)const;
    
    std::shared_ptr<Tcb> &getEstablishedConnection(SocketPair &pair);

    bool hasBoundPort(uint16_t port) const;

    void onPacket(std::shared_ptr<Tcb> tcb ,std::vector<uint8_t> &buffer);

    void onAccept(std::vector<uint8_t> &buffer);

    void run();

    void stop();

    bool addListener(std::shared_ptr<PassiveSock> sock);

    void removeListener(std::shared_ptr<PassiveSock> sock);

    bool addConnection(std::shared_ptr<Tcb> tcb);

    void packetProcessing(std::vector<uint8_t> &buffer);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    void worker(std::future<bool> stop);
};
#endif