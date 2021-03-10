#ifndef UTCP_ISOCK_HPP
#define UTCP_ISOCK_HPP

#include <memory>
#include <stdint.h>
#include <vector>

class ConnectionSock;

class ISock
{
public:
    virtual int bind(uint16_t port) = 0;

    virtual int connect(uint32_t addr, uint16_t port) = 0;

    virtual std::shared_ptr<ISock> accept() = 0;

    virtual int send(const std::vector<uint8_t> &buffer) = 0;

    virtual int recv(std::vector<uint8_t> &buffer) = 0;

    virtual int close() = 0;

    virtual ~ISock() = default;
};

#endif