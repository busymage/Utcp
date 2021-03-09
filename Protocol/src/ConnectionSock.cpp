#include <Protocol/ConnectionSock.hpp>
#include <Protocol/SocketPair.hpp>
#include <Protocol/Tcp.hpp>
#include <Protocol/Tcb.hpp>
#include <arpa/inet.h>
#include <condition_variable>
#include <mutex>
#include <queue>

constexpr uint32_t LocalAddr = 0xa000002;

struct ConnectionSock::Impl{
    std::shared_ptr<Tcb> tcb;

    std::mutex lock;

    std::condition_variable sendCond;

    std::condition_variable recvCond;

    Tcp *tcp;

    bool IsWriteable()
    {
        return tcb->snd.wnd > 0;
    }

    bool IsReadable()
    {
        return tcb->recvQueue.size() > 0;
    }
};

ConnectionSock::ConnectionSock(Tcp *tcp, std::shared_ptr<Tcb> tcb)
:impl_(new Impl)
{
    impl_->tcp = tcp;
    impl_->tcb = tcb;
}

ConnectionSock::~ConnectionSock() = default;

int ConnectionSock::bind(uint16_t port)
{
    return 0;
}
int ConnectionSock::connect(uint32_t addr, uint16_t port)
{
    return 0;
}

ISock *ConnectionSock::accept()
{
    return 0;
}

int ConnectionSock::send(const std::vector<uint8_t> &buffer)
{
    std::unique_lock<std::mutex> lock(impl_->lock);
    if(impl_->tcb->snd.wnd == 0){
        impl_->sendCond.wait(lock, [this](){
            return impl_->IsWriteable();
        });
    }
    uint16_t avilableSize = impl_->tcb->snd.wnd <= buffer.size() ?
                            impl_->tcb->snd.wnd : buffer.size();
    impl_->tcb->sndQueue.insert(impl_->tcb->sndQueue.end(), buffer.data(), buffer.data() + avilableSize);
    impl_->tcp->send(impl_->tcb);
    return avilableSize;
}

int ConnectionSock::recv(std::vector<uint8_t> &buffer)
{
    //may add some flag to indicate whether or not the peer is close.
    std::unique_lock<std::mutex> lock(impl_->lock);
    if(impl_->tcb->recvQueue.size() == 0){
        impl_->recvCond.wait(lock, [this](){
            return impl_->IsReadable() || TcpState::CLOSE_WAIT == impl_->tcb->state;
        });
    }
    buffer = impl_->tcb->recvQueue;
    impl_->tcb->recvQueue.clear();
    impl_->tcb->rcv.wnd += buffer.size();
    return buffer.size();
}

int ConnectionSock::close()
{
    impl_->tcp->closeConnection(shared_from_this());
    return 0;
}

SocketPair &ConnectionSock::name() const
{
    return impl_->tcb->addr;
}

std::shared_ptr<Tcb> ConnectionSock::tcb() const
{
    return impl_->tcb;
}

void ConnectionSock::RecvFromTcp(const uint8_t *data , int len)
{
    std::lock_guard<std::mutex> lock(impl_->lock);
    impl_->tcb->recvQueue.insert(impl_->tcb->recvQueue.end(), data, data + len);
    impl_->recvCond.notify_all();
}

void ConnectionSock::notifyPeerClose(TcpState state)
{
    std::lock_guard<std::mutex> lock(impl_->lock);
    impl_->tcb->state = state;
    impl_->recvCond.notify_all();
}