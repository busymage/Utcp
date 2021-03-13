#ifndef UTCP_SOCKET_HPP
#define UTCP_SOCKET_HPP

#include <memory>
#include <stdint.h>
#include <vector>
#include <string>

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

    struct ErrorCode{
        std::string msg;
    };

public:

    Socket(Tcp *tcp, SocketType type);

    int bind(uint16_t port, ErrorCode &code);

    int connect(uint32_t addr, uint16_t port, ErrorCode &code);

    Socket accept(ErrorCode &code);

    int send(const std::vector<uint8_t> &buffer, ErrorCode &code);

    int recv(std::vector<uint8_t> &buffer, ErrorCode &code);

    int close();

    ~Socket();
    Socket(const Socket&);

private: 
    struct Impl;
    std::unique_ptr<Impl> impl_;

    Socket(std::shared_ptr<ISock> sock, SocketType type);
};

#endif