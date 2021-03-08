#include <Protocol/PassiveSock.hpp>
#include <Protocol/SocketPair.hpp>
#include <Protocol/Tcp.hpp>
#include <Protocol/Tcb.hpp>
#include <arpa/inet.h>
#include <queue>

constexpr uint32_t LocalAddr = 0xa000002;

struct PassiveSock::Impl{
    std::shared_ptr<Tcb> tcb;
    std::queue<std::shared_ptr<ISock>> backlog;

    std::shared_ptr<Tcp> tcp;
};

PassiveSock::PassiveSock(std::shared_ptr<Tcp> tcp)
:impl_(new Impl)
{
    impl_->tcp = tcp;
    SocketPair pair = {
        LocalAddr,
        0,
        0,
        0
    };
    impl_->tcb = std::make_shared<Tcb>(pair);
}

PassiveSock::~PassiveSock(){
    //close();
}

int PassiveSock::bind(uint16_t port)
{
    impl_->tcb->addr.sport = port;
    return impl_->tcp->addListener(shared_from_this());
}
int PassiveSock::connect(uint32_t addr, uint16_t port)
{
    return 0;
}

ISock *PassiveSock::accept()
{
    if(impl_->backlog.empty())
    {
        return nullptr;
    }
    ISock *sock = impl_->backlog.front().get();
    impl_->backlog.pop();
    return sock;
}
int PassiveSock::send(const std::vector<uint8_t> &buffer)
{
    return 0;
}
int PassiveSock::recv(std::vector<uint8_t> &buffer)
{
    return 0;
}

int PassiveSock::close()
{
    impl_->tcp->removeListener(shared_from_this());
    return 0;
}

uint16_t PassiveSock::port() const
{
    return impl_->tcb->addr.sport;
}