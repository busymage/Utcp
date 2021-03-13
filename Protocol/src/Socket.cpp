#include <Protocol/Socket.hpp>
#include <Protocol/ISock.hpp>
#include <Protocol/ConnectionSock.hpp>
#include <Protocol/PassiveSock.hpp>
#include <assert.h>

struct Socket::Impl
{
    std::shared_ptr<ISock> sock;
    SocketType type;
};

Socket::Socket(Tcp *tcp, SocketType type)
:impl_(new Impl)
{
    impl_->type = type;
    if(type == SocketType::ACTIVE){
        impl_->sock = std::make_shared<ConnectionSock>(tcp);
    }else if(type == SocketType::PASSIVE){
        impl_->sock = std::make_shared<PassiveSock>(tcp);
    }
}

Socket::Socket(std::shared_ptr<ISock> sock, SocketType type)
:impl_(new Impl)
{
    impl_->sock = sock;
    impl_->type = type;
}

int Socket::bind(uint16_t port, ErrorCode &code)
{
    if(impl_->type != SocketType::PASSIVE){
        code.msg = "Socket type not supprt (bind) method.";
        return -1;
    }
    int ret =  impl_->sock->bind(port);
    if(ret == -1){
        code.msg = "Address already bind\n";
        return -1;
    }
    return 0;
}

int Socket::connect(uint32_t addr, uint16_t port, ErrorCode &code)
{
    if(impl_->type != SocketType::ACTIVE){
        code.msg = "Socket type not supprt (connect) method.";
        return -1;
    }
    int ret =  impl_->sock->connect(addr, port);
    if(ret == -2){
        code.msg = "Connection reset by peer";
        return -1;
    } else if(ret == -3){
        code.msg = "Connection close";
        return -1;
    } else if(ret == -4){
        code.msg = "Connection timeout";
        return -1;
    }
    return 0;
}

Socket Socket::accept(ErrorCode &code)
{
    if(impl_->type != SocketType::PASSIVE){
        code.msg = "Socket type not supprt (accpet) method.";
        return Socket(impl_->sock, SocketType::INVAILD);
    }
    auto sock = impl_->sock->accept();
    return Socket(sock, SocketType::ACTIVE);
}

int Socket::send(const std::vector<uint8_t> &buffer, ErrorCode &code)
{
    if(impl_->type != SocketType::ACTIVE){
        code.msg = "Socket type not supprt (send) method.";
        return -1;
    }
    int ret =  impl_->sock->send(buffer);
    if(ret == -2){
        code.msg = "Connection reset by peer";
        return -1;
    } else if(ret == -3){
        code.msg = "Connection close";
        return -1;
    } else if(ret == -4){
        code.msg = "Connection timeout";
        return -1;
    }
    return ret;
}

int Socket::recv(std::vector<uint8_t> &buffer, ErrorCode &code)
{
    if(impl_->type != SocketType::ACTIVE){
        code.msg = "Socket type not supprt (recv) method.";
        return -1;
    }
     int ret =  impl_->sock->recv(buffer);
    if(ret == -2){
        code.msg = "Connection reset by peer";
        return -1;
    } else if(ret == -3){
        code.msg = "Connection close";
        return -1;
    } else if(ret == -4){
        code.msg = "Connection timeout";
        return -1;
    }
    return ret;
}

int Socket::close()
{
    if(impl_->type == SocketType::INVAILD){
        return -1;
    }
    return impl_->sock->close();
}

Socket::~Socket() = default;

Socket::Socket(const Socket& other)
{
    impl_->sock = other.impl_->sock;
    impl_->type = other.impl_->type;
}