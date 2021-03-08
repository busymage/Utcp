#include <Protocol/Socket.hpp>
#include <Protocol/ISock.hpp>

struct Socket::Impl{
    ISock *sock;
};

Socket::Socket(SocketType type)
:impl_(new Impl)
{
    
}

Socket::~Socket() = default;

int Socket::bind(uint16_t port, ErrorCode &ec)
{
    return 0;
}

int Socket::connect(uint32_t addr, uint16_t port, ErrorCode &ec)
{
    return 0;
}
int Socket::send(const std::vector<uint8_t> &buffer, ErrorCode &ec)
{
    return 0;
}
int Socket::recv(std::vector<uint8_t> &buffer, ErrorCode &ec)
{   
    return 0;
}

int Socket::close()
{
    return 0;
}