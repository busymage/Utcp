#ifndef UTCP_TCP_HPP
#define UTCP_TCP_HPP

#include <future>
#include <memory>
#include <Protocol/SocketPair.hpp>
#include <thread>
#include <vector>

class INetDevice;
class ConnectionSock;
class PassiveSock;
struct Tcb;

class Tcp
{
public:
    Tcp(std::shared_ptr<INetDevice> netDev);
    ~Tcp();

    bool isEstablished(SocketPair &pair)const;
    
    std::shared_ptr<ConnectionSock> getEstablishedConnection(SocketPair &pair);

    bool hasBoundPort(uint16_t port) const;

    void onPacket(std::shared_ptr<Tcb> tcb ,std::vector<uint8_t> &buffer);

    void onAccept(std::vector<uint8_t> &buffer);

    void run();

    void stop();

    bool addListener(std::shared_ptr<PassiveSock> sock);

    void removeListener(uint16_t port);

    bool addConnection(std::shared_ptr<ConnectionSock> ConnectionSock);

    void removeConnection(SocketPair &sockname);

    void packetProcessing(std::vector<uint8_t> &buffer);

    void send(std::shared_ptr<Tcb> tcb); 

    void closeConnection(std::shared_ptr<ConnectionSock> sock);

    void connect(std::shared_ptr<ConnectionSock> sock);

    uint16_t pickARamdonPort();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    void worker(std::future<bool> stop);
};
#endif