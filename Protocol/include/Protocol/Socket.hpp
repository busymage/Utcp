#ifndef UTCP_SOCKET_HPP
#define UTCP_SOCKET_HPP

#include <memory>
#include <string>
#include <vector>

class Socket
{
public:
    struct ErrorCode{
        std::string msg;
    };

    enum class SocketType{
        active,
        Passvie
    };

public:
    Socket(SocketType type);

    ~Socket();

    int bind(uint16_t port, ErrorCode &ec);
    int connect(uint32_t addr, uint16_t port, ErrorCode &ec);
    int send(const std::vector<uint8_t> &buffer, ErrorCode &ec);
    int recv(std::vector<uint8_t> &buffer, ErrorCode &ec);
    int close();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

#endif