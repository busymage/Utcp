#ifndef UTCP_CONNECTIONSOCK_HPP
#define UTCP_CONNECTIONSOCK_HPP

#include <Protocol/ISock.hpp>
#include <Protocol/Tcb.hpp>
#include <Protocol/Tcp.hpp>
#include <memory>

class ConnectionSock : public ISock,
                    public std::enable_shared_from_this<ConnectionSock>
{
public:
    ConnectionSock(Tcp *tcp, std::shared_ptr<Tcb>);

    ~ConnectionSock();

    virtual int bind(uint16_t port) override;

    virtual int connect(uint32_t addr, uint16_t port) override;

    virtual std::shared_ptr<ISock> accept() override;

    virtual int send(const std::vector<uint8_t> &buffer) override;

    virtual int recv(std::vector<uint8_t> &buffer) override;

    virtual int close() override;

    SocketPair &name() const;

    std::shared_ptr<Tcb> tcb() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};



#endif