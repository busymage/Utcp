#include <Protocol/Tcb.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>

constexpr uint16_t WND = 65535;

Tcb::Tcb(SocketPair &sockPair)
{
    addr = sockPair;
    snd = {0};
    rcv = {0};
}

Tcb::Tcb(SocketPair &sockPair, tcphdr *th)
{
    addr = sockPair;
    snd = {0};
    snd.wnd = ntohs(th->window);
    
    rcv.wnd = WND;
    rcv.irs = ntohl(th->seq);
    rcv.nxt = ntohl(th->seq) + 1;
    rcv.up = 0;
}

bool Tcb::isSynchronizedState()
{
    return  TcpState::SYN_RECEIVED == state ||
            TcpState::ESTABLISHED == state ||
            TcpState::FIN_WAIT1 == state ||
            TcpState::FIN_WAIT2 == state ||
            TcpState::CLOSE_WAIT == state ||
            TcpState::CLOSING == state ||
            TcpState::LAST_ACK == state ||
            TcpState::TIME_WAIT == state;
}   