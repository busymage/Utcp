#include <Protocol/Tcb.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>

constexpr uint16_t WND = 65535;

Tcb::Tcb(SocketPair &sockPair)
{
    addr = sockPair;
    sndQueue.resize(WND);
    recvQueue.resize(WND);
}

Tcb::Tcb(SocketPair &sockPair, tcphdr *th)
{
    addr = sockPair;
    sndQueue.resize(WND);
    recvQueue.resize(WND);
    
    snd.wnd = ntohs(th->window);
    snd.iss = 0;
    
    rcv.wnd = WND;
    rcv.irs = ntohl(th->seq);
    rcv.nxt = ntohl(th->seq) + 1;
}