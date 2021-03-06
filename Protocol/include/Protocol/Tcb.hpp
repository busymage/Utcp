#ifndef UTCP_TCB_HPP
#define UTCP_TCB_HPP

#include <deque>
#include <netinet/tcp.h>
#include <ostream>
#include <Protocol/SocketPair.hpp>
#include <stdint.h>

struct SND{
    //send unacknowledged
    uint32_t una;

    //send next
    uint32_t nxt;
    
    //send window
    uint16_t wnd;

    //send urgent pointer
    uint16_t up;

    //segment sequence number used for last window update
    uint32_t wl1;

    //segment acknowledgment number used for last window update
    uint32_t wl2;

    //initial send sequence number
    uint32_t iss;
};

struct RCV{
    //recv next
    uint32_t nxt;
    
    //recv window
    uint16_t wnd;

    //recv urgent pointer
    uint16_t up;

    //initial receive sequence number
    uint32_t irs;
};

enum TcpState{
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    CLOSE_WAIT,
    LAST_ACK,
    FIN_WAIT1,
    FIN_WAIT2,
    CLOSING,
    TIME_WAIT
};

struct Tcb{
    SocketPair addr;
    TcpState state;
    SND snd;
    RCV rcv;
    std::deque<uint8_t> sndQueue;
    std::deque<uint8_t> recvQueue;

    Tcb(SocketPair &addr);
    Tcb(SocketPair &addr, tcphdr *th);

    bool isSynchronizedState();
};

inline std::ostream& operator<<(std::ostream &os, Tcb &tcb)
{
    return os << "Send:\n" << "\tuna: " << tcb.snd.una <<
        " nxt: " << tcb.snd.nxt << " wnd: " << tcb.snd.wnd << 
        "\nRecv:\n" << "\tnxt: " << tcb.snd.nxt <<
        " wnd: " << tcb.rcv.wnd << std::endl;
}

#endif