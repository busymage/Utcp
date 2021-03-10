#include <Protocol/PassiveSock.hpp>
#include <Protocol/SocketPair.hpp>
#include <Protocol/Tcp.hpp>
#include <Protocol/Tcb.hpp>
#include <arpa/inet.h>
#include <queue>
#include <condition_variable>
#include <mutex>

constexpr uint32_t LocalAddr = 0xa000002;

struct PassiveSock::Impl{
    std::shared_ptr<Tcb> tcb;
    std::queue<std::shared_ptr<ISock>> backlog;

    std::mutex lock;

    std::condition_variable backlogCond;

    Tcp *tcp;
};

PassiveSock::PassiveSock(Tcp *tcp)
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
}

int PassiveSock::bind(uint16_t port)
{
    impl_->tcb->state = TcpState::LISTEN;
    impl_->tcb->addr.sport = htons(port);
    return impl_->tcp->addListener(shared_from_this());
}
int PassiveSock::connect(uint32_t addr, uint16_t port)
{
    return 0;
}

std::shared_ptr<ISock> PassiveSock::accept()
{
    
    std::unique_lock<std::mutex> lock(impl_->lock);
    if(impl_->backlog.empty())
    {
        impl_->backlogCond.wait(lock, [this](){
            return impl_->backlog.empty() == false;
        });
    }
    auto sock = impl_->backlog.front();
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
    impl_->tcp->removeListener(impl_->tcb->addr.sport);
    return 0;
}

SocketPair PassiveSock::name() const
{
    return impl_->tcb->addr;
}

std::shared_ptr<Tcb> PassiveSock::tcb() const
{
    return impl_->tcb;
}

void PassiveSock::acceptSock(std::shared_ptr<ISock> sock)
{
    std::lock_guard<std::mutex> lock(impl_->lock);
    impl_->backlog.push(sock);
    impl_->backlogCond.notify_all();
}

int PassiveSock::waitingAcceptCount() const
{
    std::lock_guard<std::mutex> lock(impl_->lock);
    return impl_->backlog.size();
}