#ifndef UTCP_INETDEVICE_HPP
#define UTCP_INETDEVICE_HPP

#include <stddef.h>
#include <stdint.h>

class INetDevice{
public:
    virtual int send(const uint8_t *data, size_t len) = 0;
    virtual int recv(uint8_t *data, size_t len) = 0;
    virtual ~INetDevice() = default;
};

#endif