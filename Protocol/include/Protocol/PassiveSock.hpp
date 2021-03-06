#ifndef UTCP_PASSIVESOCK_HPP
#define UTCP_PASSIVESOCK_HPP

#include <Protocol/ISock.hpp>
#include <Protocol/Tcp.hpp>
#include <memory>

class PassiveSock : public ISock,
                    public std::enable_shared_from_this<PassiveSock>
{
public:
    PassiveSock(Tcp *tcp);

    ~PassiveSock();

    virtual int bind(uint16_t port) override;

    virtual int connect(uint32_t addr, uint16_t port) override;

    virtual std::shared_ptr<ISock> accept() override;

    virtual int send(const std::vector<uint8_t> &buffer) override;

    virtual int recv(std::vector<uint8_t> &buffer) override;

    virtual int close() override;

    SocketPair name() const;

    std::shared_ptr<Tcb> tcb() const;

    void acceptSock(std::shared_ptr<ISock> sock);

    int waitingAcceptCount() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};



#endif