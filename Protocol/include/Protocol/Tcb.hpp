#ifndef UTCP_TCB_HPP
#define UTCP_TCB_HPP

#include <vector>
#include <netinet/tcp.h>
#include <ostream>
#include <Protocol/SocketPair.hpp>
#include <Protocol/Timer.hpp>
#include <stdint.h>
#include <condition_variable>
#include <mutex>

#define MIN_RTO 200
#define MAX_RTO 12800

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
    CLOSE,
    ABORT,
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
    std::vector<uint8_t> sndQueue;
    std::vector<uint8_t> recvQueue;

    std::mutex lock;

    std::condition_variable sndCond;
    std::condition_variable rcvCond;
    std::condition_variable estCond;

    Timer retransmissionTimer;

    std::vector<uint8_t> rtmixQueue;

    //milliseconds
    uint32_t rto = MIN_RTO;

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