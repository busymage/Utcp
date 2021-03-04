#ifndef UTCP_TCP_HPP
#define UTCP_TCP_HPP

#include <memory>
#include <Protocol/SocketPair.hpp>
#include <vector>

class Tcp
{
public:
    Tcp(int netDev);
    ~Tcp();

    bool isEstablished(SocketPair &pair)const;

    std::shared_ptr<Tcb> &getEstablishedConnection(SocketPair &pair);

    bool hasBoundPort(uint16_t port) const;

    void onPacket(std::shared_ptr<Tcb> tcb ,std::vector<uint8_t> &buffer);

    void onAccept(std::vector<uint8_t> &buffer);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
#endif