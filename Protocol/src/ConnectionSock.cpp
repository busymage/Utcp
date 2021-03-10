#include <Protocol/ConnectionSock.hpp>
#include <Protocol/SocketPair.hpp>
#include <Protocol/Tcp.hpp>
#include <Protocol/Tcb.hpp>
#include <arpa/inet.h>
#include <queue>

constexpr uint32_t LocalAddr = 0xa000002;

struct ConnectionSock::Impl{
    std::shared_ptr<Tcb> tcb;
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

std::shared_ptr<ISock> ConnectionSock::accept()
{
    return {};
}

int ConnectionSock::send(const std::vector<uint8_t> &buffer)
{
    std::unique_lock<std::mutex> lock(impl_->tcb->lock);

    //the connection is reset by peer.
    if(impl_->tcb->state == TcpState::CLOSE){
        return -2;
    }

    //error:  connection closing
    if(impl_->tcb->state == TcpState::FIN_WAIT1 ||
    impl_->tcb->state == TcpState::FIN_WAIT2 ||
    impl_->tcb->state == TcpState::CLOSING ||
    impl_->tcb->state == TcpState::LAST_ACK ||
    impl_->tcb->state == TcpState::TIME_WAIT){
        return -3;
    }

    if(impl_->tcb->snd.wnd == 0){
        impl_->tcb->sndCond.wait(lock, [this](){
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
    std::unique_lock<std::mutex> lock(impl_->tcb->lock);
    
    //the connection is reset by peer.
    if(impl_->tcb->state == TcpState::CLOSE){
        return -2;
    }
    
    //peer clsoe send. only get data from recvQueue.
    if(impl_->tcb->state == TcpState::CLOSE_WAIT){
        buffer = impl_->tcb->recvQueue;
        impl_->tcb->recvQueue.clear();
        impl_->tcb->rcv.wnd += buffer.size();
        return buffer.size();
    }
    //error:  connection closing
    if(impl_->tcb->state == TcpState::CLOSING ||
        impl_->tcb->state == TcpState::LAST_ACK ||
        impl_->tcb->state == TcpState::TIME_WAIT){
        return -3;
    }
    
    if(impl_->tcb->recvQueue.size() == 0){
        impl_->tcb->rcvCond.wait(lock, [this](){
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