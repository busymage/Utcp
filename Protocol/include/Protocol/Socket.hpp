#ifndef UTCP_SOCKET_HPP
#define UTCP_SOCKET_HPP

#include <memory>
#include <stdint.h>
#include <vector>

class Tcp;
class ISock;

class Socket
{
public:
    enum class SocketType{
        ACTIVE,
        PASSIVE,
        INVAILD
    };

public:

    Socket(Tcp *tcp, SocketType type);

    int bind(uint16_t port);

    int connect(uint32_t addr, uint16_t port);

    Socket accept();

    int send(const std::vector<uint8_t> &buffer);

    int recv(std::vector<uint8_t> &buffer);

    int close();

    ~Socket();
    Socket(const Socket&);

private: 
    struct Impl;
    std::unique_ptr<Impl> impl_;

    Socket(std::shared_ptr<ISock> sock, SocketType type);
};

#endif