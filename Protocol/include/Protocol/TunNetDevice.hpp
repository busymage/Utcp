#ifndef UTCP_TUNNETDEVICE_HPP
#define UTCP_TUNNETDEVICE_HPP

#include <memory>
#include <Protocol/INetDevice.hpp>
#include <stdint.h>

class TunNetDevice : public INetDevice{
public:
    TunNetDevice();
    ~TunNetDevice();
    virtual int send(const uint8_t *data, size_t len) override;
    virtual int recv(uint8_t *data, size_t len) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

#endif