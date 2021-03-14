#include <Protocol/PacketBuilder.hpp>
#include <Protocol/ChecksumCalc.hpp>
#include <Protocol/ConnectionSock.hpp>
#include <Protocol/INetDevice.hpp>
#include <Protocol/PassiveSock.hpp>
#include <Protocol/Segment.hpp>
#include <Protocol/SocketPair.hpp>
#include <Protocol/Tcb.hpp>
#include <Protocol/Tcp.hpp>
#include <Protocol/Timer.hpp>
#include <chrono>
#include <future>
#include <iostream>
#include <map>
#include <math.h>
#include <memory>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>

constexpr const uint16_t RecvWnd = 65535;

constexpr const uint16_t MSS = 536;

std::string addrToString(uint32_t addr)
{
    std::string str;
    uint8_t *start = (uint8_t *)&addr;
    for (int i = 0; i < 4; i++)
    {
        str += std::to_string(start[i]);
        if (i < 3)
        {
            str += '.';
        }
    }
    return str;
}

void printTcphdrInfo(const std::string &prefix, uint32_t saddr, uint32_t daddr, tcphdr &th)
{
    HrTimePoint now = std::chrono::high_resolution_clock::now();
    time_t tt = std::chrono::high_resolution_clock::to_time_t(now);
    printf("[%s] ", ctime(&tt));
    printf("%s ", prefix.c_str());
    printf("%s:%u > %s:%u ", addrToString(saddr).c_str(), ntohs(th.source),
           addrToString(daddr).c_str(), ntohs(th.dest));
    printf("seq %u, ack %u win %u", ntohl(th.seq), ntohl(th.ack_seq), ntohs(th.window));
    printf("[%s%s%s%s%s%s]", th.urg ? "U" : "",
           th.ack ? "." : "",
           th.psh ? "P" : "",
           th.rst ? "R" : "",
           th.syn ? "S" : "",
           th.fin ? "F" : "");
    printf("\n");
}

void setDefaultValueForTcpHeader(std::shared_ptr<Tcb> tcb, tcphdr &th)
{
    memset(&th, 0, sizeof(tcphdr));
    th.source = tcb->addr.sport;
    th.dest = tcb->addr.dport;
    th.seq = htonl(tcb->snd.nxt);
    th.ack_seq = htonl(tcb->rcv.nxt);
    th.doff = 5;
    th.window = htons(tcb->rcv.wnd);
}

tcphdr buildAckSegment(std::shared_ptr<Tcb> tcb, uint32_t ack_seq)
{
    tcphdr resTcpHdr = {0};
    setDefaultValueForTcpHeader(tcb, resTcpHdr);
    resTcpHdr.ack_seq = htonl(ack_seq);
    resTcpHdr.ack = 1;
    resTcpHdr.check = caclTcpChecksum(&resTcpHdr, 20, tcb->addr.saddr, tcb->addr.daddr);
    return resTcpHdr;
}

std::vector<uint8_t> buildRstPacket(std::shared_ptr<Tcb> tcb)
{
    tcphdr resTcpHdr = {0};
    setDefaultValueForTcpHeader(tcb, resTcpHdr);
    resTcpHdr.rst = 1;
    resTcpHdr.check = caclTcpChecksum(&resTcpHdr, 20, tcb->addr.saddr, tcb->addr.daddr);
    PacketBuilder pktBuilder(tcb->addr.daddr, tcb->addr.saddr,
                             &resTcpHdr, 20);
    return pktBuilder.packet();
}

bool isBetween(uint32_t seq, uint32_t start, uint32_t end)
{
    //should care about warpping.
    return seq >= start && seq < end;
}

template <typename T>
T min(T lhs, T rhs)
{
    return lhs <= rhs ? lhs : rhs;
}

struct Tcp::Impl
{
    std::shared_ptr<INetDevice> netDev;

    std::map<SocketPair, std::shared_ptr<ConnectionSock>> synBacklog;

    std::map<SocketPair, std::shared_ptr<ConnectionSock>> establishedConnection;

    std::map<uint16_t, std::shared_ptr<PassiveSock>> listener;

    bool start = false;

    std::mutex lock;

    std::thread workerThread;

    //stop signal
    std::promise<bool> stop;

    uint8_t portBitmap[UINT16_MAX / 8] = {0};

    std::map<std::shared_ptr<Tcb>, Timer *> RetransmissionTimers;

    void removeTimer(std::shared_ptr<Tcb> tcb)
    {
        std::lock_guard<std::mutex> guard(lock);
        auto it = RetransmissionTimers.find(tcb);
        if (it != RetransmissionTimers.end())
        {
            RetransmissionTimers.erase(it);
        }
    }

    bool AddTimer(std::shared_ptr<Tcb> tcb)
    {
        std::lock_guard<std::mutex> guard(lock);
        auto it = RetransmissionTimers.find(tcb);
        if (it != RetransmissionTimers.end())
        {
            return false;
        }
        RetransmissionTimers[tcb] = &tcb->retransmissionTimer;
        return true;
    }

    void addRtmixDataTimerIfNotAdd(std::shared_ptr<Tcb> tcb)
    {
        if (RetransmissionTimers.find(tcb) == RetransmissionTimers.end())
        {
            tcb->rto = MIN_RTO;
            tcb->retransmissionTimer.expired = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(tcb->rto);
            tcb->retransmissionTimer.handler = [this, tcb]() {
                reTransmitData(tcb);
            };
            AddTimer(tcb);
        }
    }

    void processTimer()
    {
        std::vector<std::shared_ptr<Tcb>> shouldDelTimer;
        HrTimePoint now = std::chrono::high_resolution_clock::now();
        std::lock_guard<std::mutex> guard(lock);
        for (auto it = RetransmissionTimers.begin(); it != RetransmissionTimers.end(); it++)
        {
            auto tcb = it->first;
            auto timer = it->second;
            if (timer->expired <= now)
            {
                printf("Timeout: ");
                timer->handler();
                //reset timer
                tcb->rto *= 2;
                if (tcb->rto > MAX_RTO)
                {
                    shouldDelTimer.push_back(tcb);
                    continue;
                }
                timer->expired = now + std::chrono::milliseconds(tcb->rto);
            }
        }

        for (auto tcb : shouldDelTimer)
        {
            auto it = RetransmissionTimers.find(tcb);
            RetransmissionTimers.erase(it);
            {
                std::lock_guard<std::mutex> tcbLock(tcb->lock);
                if (tcb->state == TcpState::SYN_SENT)
                {
                    tcb->estCond.notify_one();
                }
                else if (tcb->state == TcpState::ESTABLISHED)
                {
                    tcb->rcvCond.notify_one();
                }
                tcb->state = TcpState::ABORT;
            }
            auto conn = establishedConnection.find(tcb->addr);
            establishedConnection.erase(conn);
        }
    }

    void transmitSyn(std::shared_ptr<Tcb> tcb)
    {
        tcphdr *th = new tcphdr;
        setDefaultValueForTcpHeader(tcb, *th);
        th->syn = 1;
        th->seq = htonl(tcb->snd.iss);
        calcTcpAndSend(tcb->addr, *th, sizeof(tcphdr));
    }

    void transmitSynAck(std::shared_ptr<Tcb> tcb)
    {
        tcphdr resTcpHdr = {0};
        setDefaultValueForTcpHeader(tcb, resTcpHdr);
        resTcpHdr.seq = htonl(tcb->snd.iss);
        resTcpHdr.ack_seq = htonl(tcb->rcv.irs + 1);
        resTcpHdr.ack = 1;
        resTcpHdr.syn = 1;
        calcTcpAndSend(tcb->addr, resTcpHdr, sizeof(tcphdr));
    }

    void transmitFin(std::shared_ptr<Tcb> tcb, uint32_t seq)
    {
        tcphdr th = {0};
        setDefaultValueForTcpHeader(tcb, th);
        th.ack = 1;
        th.fin = 1;
        th.seq = htonl(seq);
        calcTcpAndSend(tcb->addr, th, sizeof(tcphdr));
    }

    void reTransmitData(std::shared_ptr<Tcb> tcb)
    {
        std::lock_guard<std::mutex> guard(tcb->lock);
        uint32_t seq = tcb->snd.una;
        uint16_t haveWritten = 0;
        uint16_t totalLen = tcb->rtmixQueue.size();
        while (haveWritten < tcb->rtmixQueue.size())
        {
            uint16_t segLen = min<uint16_t>(MSS, totalLen - haveWritten);
            uint8_t *data = new uint8_t[sizeof(tcphdr) + segLen];
            if (data == nullptr)
            {
                perror("malloc");
                exit(1);
            }

            tcphdr *th = (tcphdr *)data;
            uint8_t *payload = data + sizeof(tcphdr);
            setDefaultValueForTcpHeader(tcb, *th);
            // RfC 1122 4.2.2.2
            // MUST set the PSH bit in the last buffered segment
            if (haveWritten + segLen >= totalLen)
            {
                th->psh = 1;
            }
            th->ack = 1;
            th->seq = htonl(seq);
            memcpy(payload, tcb->rtmixQueue.data() + haveWritten, segLen);
            calcTcpAndSend(tcb->addr, *th, sizeof(tcphdr) + segLen);

            seq += segLen;
            haveWritten += segLen;
        }

        if (TcpState::FIN_WAIT1 == tcb->state || TcpState::LAST_ACK == tcb->state)
        {
            transmitFin(tcb, seq);
        }
    }

    bool setPortifNotSet(uint16_t port)
    {
        if (port == 0)
        {
            return portBitmap[0] & 1;
        }
        uint16_t index = UINT16_MAX / 8;
        uint8_t distance = UINT16_MAX % 8;
        int num = (int)pow(2, distance);
        if ((portBitmap[index] & num) != num)
        {
            portBitmap[index] | num;
            return true;
        }
        return false;
    }

    bool checkSequenceNumber(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if (tcb->rcv.wnd == 0)
        {
            //<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            //SEG.SEQ = RCV.NXT
            if (seg.dataLen() > 0 || seg.seq() != tcb->rcv.nxt)
            {
                return false;
            }
        }
        //RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        if (!isBetween(seg.seq(), tcb->rcv.nxt, tcb->rcv.nxt + tcb->rcv.wnd))
        {
            return false;
        }
        return true;
    }

    void synSent(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if (seg.ack())
        {
            if (seg.ackSeq() <= tcb->snd.iss || seg.ackSeq() > tcb->snd.nxt)
            {
                if (!seg.rst())
                {
                    sendAckErrorReset(tcb, seg.ackSeq());
                }
                return;
            }
            if (tcb->snd.una > seg.ackSeq() && seg.ackSeq() > tcb->snd.nxt)
            {
                return;
            }
        }

        if (seg.rst())
        {
            resetConn(tcb);
            return;
        }

        if (seg.syn())
        {
            if (seg.ack())
            {
                tcb->rcv.nxt = seg.seq() + 1;
                tcb->rcv.irs = seg.seq();
                tcb->snd.una = seg.ackSeq();

                tcb->snd.wnd = seg.wnd();
                tcb->snd.wl1 = seg.seq();
                tcb->snd.wl2 = seg.ackSeq();
                //clear retransmission queue
                removeTimer(tcb);

                if (tcb->snd.una > tcb->snd.iss)
                {
                    tcb->state = TcpState::ESTABLISHED;
                    sendAcknowledgment(tcb);
                    auto sock = getHalfConnection(tcb->addr);
                    removeHalfConnection(tcb->addr);
                    addConnection(sock);
                }
            }
            else
            {
                removeTimer(tcb);

                tcb->state = TcpState::SYN_RECEIVED;
                tcphdr th = {0};
                setDefaultValueForTcpHeader(tcb, th);
                th.seq = tcb->snd.iss;
                th.syn = 1;
                th.ack = 1;

                calcTcpAndSend(tcb->addr, th, sizeof(tcphdr));
                //start timer
                tcb->rto = MIN_RTO;
                tcb->retransmissionTimer.expired = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(tcb->rto);
                tcb->retransmissionTimer.handler = [this, tcb]() {
                    transmitSynAck(tcb);
                };
                AddTimer(tcb);
            }
        }
    }

    bool synRecvived(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        //SND.UNA =< SEG.ACK =< SND.NXT
        if (seg.ackSeq() < tcb->snd.una ||
            seg.ackSeq() > tcb->snd.nxt)
        {
            tcphdr th = {0};
            setDefaultValueForTcpHeader(tcb, th);
            th.seq = htonl(seg.ackSeq());
            th.rst = 1;
            calcTcpAndSend(tcb->addr, th, sizeof(tcphdr));
            return false;
        }
        tcb->state = TcpState::ESTABLISHED;

        auto sock = getHalfConnection(tcb->addr);
        removeHalfConnection(tcb->addr);
        addConnection(sock);

        //add sock to backlog
        auto connection = establishedConnection[tcb->addr];
        auto accpetor = listener[tcb->addr.sport];
        accpetor->acceptSock(connection);

        //delete timer
        removeTimer(tcb);

        if (seg.fin())
        {
            tcb->rcv.nxt = seg.seq() + 1;
            sendAcknowledgment(tcb);
        }
        return true;
    }

    bool established(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if (!checkAck(tcb, seg))
        {
            return false;
        }
        if (seg.dataLen() > 0)
        {
            auto conn = establishedConnection[tcb->addr];
            receiveData(conn, seg);
            sendAcknowledgment(tcb);
        }
        if (seg.fin())
        {
            tcb->rcv.nxt = seg.seq() + 1;
            tcb->state = TcpState::CLOSE_WAIT;
            sendAcknowledgment(tcb);
        }
        return true;
    }

    bool lastAck(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if (!checkAck(tcb, seg))
        {
            return false;
        }
        removeTimer(tcb);
        if (seg.fin())
        {
            tcb->rcv.nxt = seg.seq() + 1;
            sendAcknowledgment(tcb);
        }
        auto it = establishedConnection.find(tcb->addr);
        establishedConnection.erase(it);
        return true;
    }

    bool finWait1(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if (!checkAck(tcb, seg))
        {
            return false;
        }
        removeTimer(tcb);
        if (seg.ackSeq() == tcb->snd.nxt)
        {
            tcb->state = TcpState::FIN_WAIT2;
        }
        if (seg.dataLen() > 0)
        {
            sendAcknowledgment(tcb);
        }
        //Simultaneous Close
        if (seg.fin())
        {
            tcb->rcv.nxt = 1 + seg.seq();
            sendAcknowledgment(tcb);
            if (tcb->state == TcpState::FIN_WAIT2)
            {
                tcb->state = TcpState::TIME_WAIT;
            }
            else
            {
                tcb->state = TcpState::CLOSING;
            }
            return true;
        }
        return true;
    }

    bool finWait2(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if (!checkAck(tcb, seg))
        {
            return false;
        }
        if (seg.dataLen() > 0)
        {
            sendAcknowledgment(tcb);
        }
        if (seg.fin())
        {
            tcb->state = TcpState::TIME_WAIT;
            tcb->rcv.nxt = seg.seq() + 1;
            sendAcknowledgment(tcb);
        }
        return true;
    }

    bool closeWait(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if (!checkAck(tcb, seg))
        {
            return false;
        }
        if (seg.fin())
        {
            tcb->rcv.nxt = seg.seq() + 1;
            sendAcknowledgment(tcb);
        }
        return true;
    }

    bool closing(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if (!checkAck(tcb, seg))
        {
            return false;
        }
        //if the ACK acknowledges our FIN then enter the TIME-WAIT state,
        //otherwise ignore the segment.
        if (seg.ackSeq() == tcb->snd.nxt)
        {
            tcb->state = TcpState::TIME_WAIT;
        }
        if (seg.fin())
        {
            tcb->rcv.nxt = seg.seq() + 1;
            sendAcknowledgment(tcb);
        }
        return true;
    }

    bool timeWait(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        //The only thing that can arrive in this state is a
        //retransmission of the remote FIN.  Acknowledge it, and restart
        //the 2 MSL timeout.
        if (seg.fin())
        {
            tcb->rcv.nxt = seg.seq() + 1;
            sendAcknowledgment(tcb);
            auto it = establishedConnection.find(tcb->addr);
            establishedConnection.erase(it);
        }
        return true;
    }

    bool checkAck(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        //SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
        if (tcb->snd.una < seg.ackSeq() && seg.ackSeq() <= tcb->snd.nxt)
        {
            //remove retransmission queue
            if (seg.ackSeq() == tcb->snd.nxt)
            {
                //all data is acknowledgment.
                tcb->rtmixQueue.clear();
                removeTimer(tcb);
            }
            else
            {
                uint16_t ackBytes = seg.ackSeq() - tcb->snd.una;
                if (tcb->rtmixQueue.size() > 0)
                {
                    tcb->rtmixQueue.erase(tcb->rtmixQueue.begin(), tcb->rtmixQueue.begin() + ackBytes);
                }
            }
            tcb->snd.una = seg.ackSeq();

            //update send window
            if (tcb->snd.wl1 <= seg.seq() && tcb->snd.wl2 <= seg.ackSeq())
            {
                tcb->snd.wnd = seg.wnd();
                tcb->snd.wl1 = seg.seq();
                tcb->snd.wl2 = seg.ackSeq();
            }
            return true;
        }
        else if (seg.ackSeq() < tcb->snd.una)
        {
            //ingore
            return true;
        }
        else if (seg.ackSeq() > tcb->snd.nxt)
        {
            auto th = buildAckSegment(tcb, seg.seq());
            sendPacket(tcb->addr, th, sizeof(tcphdr));
            return false;
        }
        return true;
    }

    void receiveData(std::shared_ptr<ConnectionSock> sock, Segment &seg)
    {
        auto tcb = sock->tcb();
        uint8_t *data = seg.data();
        uint16_t minSize = seg.dataLen() >= tcb->rcv.wnd ? tcb->rcv.wnd : seg.dataLen();
        tcb->recvQueue.insert(tcb->recvQueue.end(), data, data + minSize);
        tcb->rcv.nxt += minSize;
        tcb->rcv.wnd -= minSize;
    }

    void sendAcknowledgment(std::shared_ptr<Tcb> tcb)
    {
        auto th = buildAckSegment(tcb, tcb->rcv.nxt);
        sendPacket(tcb->addr, th, sizeof(tcphdr));
    }

    void sendAckErrorReset(std::shared_ptr<Tcb> tcb, uint32_t ack)
    {
        tcphdr th = {0};
        setDefaultValueForTcpHeader(tcb, th);
        th.seq = htonl(ack);
        th.rst = 1;
        calcTcpAndSend(tcb->addr, th, sizeof(tcphdr));
    }

    void deleteConn(std::shared_ptr<Tcb> tcb)
    {
        if (tcb->state == TcpState::SYN_SENT || tcb->state == TcpState::SYN_RECEIVED)
        {
            removeHalfConnection(tcb->addr);
        }
        else
        {
            removeConnection(tcb->addr);
        }
    }

    void calcTcpAndSend(SocketPair addr, tcphdr &th, uint16_t segLen)
    {
        th.check = caclTcpChecksum(&th, segLen, addr.saddr, addr.daddr);
        sendPacket(addr, th, segLen);
    }

    void sendPacket(SocketPair addr, tcphdr &th, uint16_t segLen)
    {
        printTcphdrInfo("Send", addr.saddr, addr.daddr, th);
        PacketBuilder pktBuilder(addr.saddr, addr.daddr, &th, segLen);
        auto outBuffer = pktBuilder.packet();
        netDev->send(outBuffer.data(), outBuffer.size());
    }

    void resetConn(std::shared_ptr<Tcb> tcb)
    {
        tcb->state = TcpState::CLOSE;
        tcb->snd = {0};
        tcb->rcv = {0};
        tcb->sndQueue.clear();
        tcb->recvQueue.clear();
        deleteConn(tcb);
    }

    std::shared_ptr<ConnectionSock> getHalfConnection(SocketPair &sockname)
    {
        std::lock_guard<std::mutex> tcpLock(lock);
        auto it = synBacklog.find(sockname);
        if (it != synBacklog.end())
        {
            return synBacklog[sockname];
        }
        return {};
    }

    bool addHalfConnection(std::shared_ptr<ConnectionSock> sock)
    {
        std::lock_guard<std::mutex> tcpLock(lock);
        if (synBacklog.find(sock->name()) != synBacklog.end())
        {
            return false;
        }
        synBacklog[sock->name()] = sock;
        return true;
    }

    void removeHalfConnection(SocketPair &sockname)
    {
        std::lock_guard<std::mutex> tcpLock(lock);
        auto it = synBacklog.find(sockname);
        if (it != synBacklog.end())
        {
            synBacklog.erase(it);
        }
    }

    bool isEstablishing(SocketPair &pair)
    {
        std::lock_guard<std::mutex> tcpLock(lock);
        return synBacklog.find(pair) != synBacklog.end();
    }

    bool addConnection(std::shared_ptr<ConnectionSock> sock)
    {
        std::lock_guard<std::mutex> tcpLock(lock);
        if (establishedConnection.find(sock->name()) != establishedConnection.end())
        {
            return false;
        }
        establishedConnection[sock->name()] = sock;
        return true;
    }

    void removeConnection(SocketPair &sockname)
    {
        std::lock_guard<std::mutex> tcpLock(lock);
        auto it = establishedConnection.find(sockname);
        if (it != establishedConnection.end())
        {
            establishedConnection.erase(it);
        }
    }
};

Tcp::Tcp(std::shared_ptr<INetDevice> netDev)
    : impl_(new Impl)
{
    impl_->netDev = netDev;
}

Tcp::~Tcp()
{
    stop();
    //remove all all sock tcp holds.
    impl_->listener.clear();
    impl_->establishedConnection.clear();
}

bool Tcp::isEstablished(SocketPair &pair) const
{
    std::lock_guard<std::mutex> tcpLock(impl_->lock);
    return impl_->establishedConnection.find(pair) != impl_->establishedConnection.end();
}

std::shared_ptr<ConnectionSock> Tcp::getEstablishedConnection(SocketPair &pair)
{
    if (isEstablished(pair))
    {
        return impl_->establishedConnection[pair];
    }
    return {};
}

bool Tcp::hasBoundPort(uint16_t port) const
{
    std::lock_guard<std::mutex> tcpLock(impl_->lock);
    return impl_->listener.find(htons(port)) != impl_->listener.end();
}

void Tcp::onPacket(std::shared_ptr<Tcb> tcb, std::vector<uint8_t> &buffer)
{
    iphdr *ih = (iphdr *)buffer.data();
    Segment seg(buffer.data() + ih->ihl * 4, ntohs(ih->tot_len) - ih->ihl * 4);

    if (tcb->state == TcpState::SYN_SENT)
    {
        impl_->synSent(tcb, seg);
        return;
    }

    //step1
    if (!impl_->checkSequenceNumber(tcb, seg))
    {
        if (seg.rst())
        {
            return;
        }
        auto th = buildAckSegment(tcb, tcb->rcv.nxt);
        impl_->sendPacket(tcb->addr, th, sizeof(tcphdr));
        return;
    }

    //step2
    if (seg.rst())
    {
        switch (tcb->state)
        {
        case TcpState::SYN_RECEIVED:
        {
            //in this state. Only Tcp hold the connection
            //User dont know it exist.
            impl_->deleteConn(tcb);
            return;
        }
        case TcpState::ESTABLISHED:
        case TcpState::FIN_WAIT1:
        case TcpState::FIN_WAIT2:
        case TcpState::CLOSE_WAIT:
            impl_->resetConn(tcb);
            break;
        case TcpState::CLOSING:
        case TcpState::LAST_ACK:
        case TcpState::TIME_WAIT:
            impl_->resetConn(tcb);
            break;
        default:
            return;
        }
    }

    //step4
    if (seg.syn())
    {
        if (tcb->isSynchronizedState())
        {
            auto outBuffer = buildRstPacket(tcb);
            impl_->netDev->send(outBuffer.data(), outBuffer.size());
            impl_->resetConn(tcb);
        }
        return;
    }

    if (!seg.ack())
    {
        return;
    }

    //step5
    switch (tcb->state)
    {
    case TcpState::SYN_RECEIVED:
        if (!impl_->synRecvived(tcb, seg))
        {
            return;
        }
        break;
    case TcpState::ESTABLISHED:
        if (!impl_->established(tcb, seg))
        {
            return;
        }
        break;
    case TcpState::LAST_ACK:
        if (impl_->lastAck(tcb, seg))
        {
            return;
        }
        break;
    case TcpState::FIN_WAIT1:
        if (!impl_->finWait1(tcb, seg))
        {
            return;
        }
        break;
    case TcpState::FIN_WAIT2:
        if (!impl_->finWait2(tcb, seg))
        {
            return;
        }
        break;
    case TcpState::CLOSE_WAIT:
        if (!impl_->closeWait(tcb, seg))
        {
            return;
        }
        break;
    case TcpState::CLOSING:
        if (!impl_->closing(tcb, seg))
        {
            return;
        }
        break;
    case TcpState::TIME_WAIT:
        if (!impl_->timeWait(tcb, seg))
        {
            return;
        }
        break;
    default:
        break;
    }
}

void Tcp::onAccept(std::vector<uint8_t> &buffer)
{
    iphdr *inetHdr = (iphdr *)buffer.data();
    tcphdr *tcpHdr = (tcphdr *)(buffer.data() + inetHdr->ihl * 4);

    //first check for an RST An incoming RST should be ignored.  Return.
    if (tcpHdr->rst)
    {
        buffer.clear();
        return;
    }

    /*
     *  second check for an ACK
        Any acknowledgment is bad if it arrives on a connection still in
        the LISTEN state.  An acceptable reset segment should be formed
        for any arriving ACK-bearing segment.  The RST should be
        formatted as follows:
          <SEQ=SEG.ACK><CTL=RST>
        Return.
    */
    if (tcpHdr->ack)
    {
        tcphdr th = {0};
        th.source = tcpHdr->dest;
        th.dest = tcpHdr->source;
        th.th_off = 5;
        th.seq = tcpHdr->ack_seq;
        th.rst = 1;
        th.window = 1234;
        th.check = caclTcpChecksum(&th, 20, inetHdr->daddr, inetHdr->saddr);
        PacketBuilder pb(inetHdr->daddr, inetHdr->saddr, &th, 20);
        std::vector<uint8_t> packet = pb.packet();
        printTcphdrInfo("Send", inetHdr->daddr, inetHdr->saddr, th);
        impl_->netDev->send(packet.data(), packet.size());
        return;
    }

    if (!tcpHdr->syn)
    {
        printf("dont have syn\n");
        return;
    }

    // inital tcb
    SocketPair sp = {
        inetHdr->daddr, //local
        tcpHdr->dest,
        inetHdr->saddr, //foregin
        tcpHdr->source};
    std::shared_ptr<Tcb> tcb = std::make_shared<Tcb>(sp, tcpHdr);

    //construct syn,ack handshake
    impl_->transmitSynAck(tcb);

    //update tcb
    tcb->snd.nxt = tcb->snd.iss + 1;
    tcb->snd.una = tcb->snd.iss;
    tcb->state = TcpState::SYN_RECEIVED;

    //add connection to syn backlog
    impl_->synBacklog[tcb->addr] = std::make_shared<ConnectionSock>(this, tcb);

    //start timer
    tcb->rto = MIN_RTO;
    tcb->retransmissionTimer.expired = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(tcb->rto);
    tcb->retransmissionTimer.handler = [this, tcb]() {
        impl_->transmitSynAck(tcb);
    };
    impl_->AddTimer(tcb);
}

void Tcp::run()
{
    if (impl_->start)
    {
        return;
    }
    impl_->start = true;
    std::future<bool> stop = impl_->stop.get_future();
    impl_->workerThread = std::thread(&Tcp::worker, this, std::move(stop));
}

void Tcp::stop()
{
    if (impl_->start)
    {
        impl_->stop.set_value(true);
        impl_->start = false;
        if (impl_->workerThread.joinable())
        {
            impl_->workerThread.join();
        }
    }
}

bool Tcp::addListener(std::shared_ptr<PassiveSock> sock)
{
    std::lock_guard<std::mutex> lock(impl_->lock);
    if (!impl_->setPortifNotSet(sock->name().sport))
    {
        return false;
    }
    if (impl_->listener.find(sock->name().sport) != impl_->listener.end())
    {
        return false;
    }
    impl_->listener[sock->name().sport] = sock;
    return true;
}

void Tcp::removeListener(uint16_t port)
{
    std::lock_guard<std::mutex> lock(impl_->lock);
    auto it = impl_->listener.find(port);
    if (it != impl_->listener.end())
    {
        impl_->listener.erase(it);
    }
}

bool Tcp::addConnection(std::shared_ptr<ConnectionSock> sock)
{
    return impl_->addConnection(sock);
}

void Tcp::removeConnection(SocketPair &sockname)
{
    impl_->removeConnection(sockname);
}

bool Tcp::addHalfConnection(std::shared_ptr<ConnectionSock> sock)
{
    return impl_->addHalfConnection(sock);
}

void Tcp::removeHalfConnection(SocketPair &sockname)
{
    impl_->removeHalfConnection(sockname);
}

bool Tcp::isEstablishing(SocketPair &pair) const
{
    return impl_->isEstablishing(pair);
}

std::shared_ptr<ConnectionSock> Tcp::getHalfConnection(SocketPair &pair)
{
    return impl_->getHalfConnection(pair);
}

void Tcp::packetProcessing(std::vector<uint8_t> &buffer)
{
    if (buffer.size() < 40)
    {
        printf("packet to small\n");
        return;
    }

    iphdr *inetHdr = (iphdr *)buffer.data();
    if (inetHdr->version != 4)
    {
        return;
    }
    if (inetHdr->protocol != 0x06)
    {
        return;
    }
    tcphdr *tcpHdr = (tcphdr *)(buffer.data() + inetHdr->ihl * 4);
    printTcphdrInfo("Recv", inetHdr->saddr, inetHdr->daddr, *tcpHdr);

    SocketPair pair = {
        inetHdr->daddr, //local
        tcpHdr->dest,
        inetHdr->saddr, //foregin
        tcpHdr->source};

    if (isEstablished(pair) || isEstablishing(pair))
    {
        std::shared_ptr<ConnectionSock> conn;
        if (isEstablished(pair))
        {
            conn = getEstablishedConnection(pair);
        }
        else
        {
            conn = getHalfConnection(pair);
        }
        auto tcb = conn->tcb();

        //lock tcb
        std::lock_guard<std::mutex> lock(tcb->lock);
        onPacket(tcb, buffer);
        if (tcb->recvQueue.size() > 0 ||
            tcb->state == TcpState::CLOSE_WAIT ||
            tcb->state == TcpState::CLOSE)
        {
            tcb->rcvCond.notify_one();
        }
        if (tcb->snd.wnd > 0 ||
            tcb->state == TcpState::CLOSE)
        {
            tcb->sndCond.notify_one();
        }
        if (tcb->state == TcpState::ESTABLISHED ||
            tcb->state == TcpState::CLOSE ||
            tcb->state == TcpState::ABORT)
        {
            tcb->estCond.notify_one();
        }
    }
    else if (hasBoundPort(ntohs(tcpHdr->dest)))
    {
        onAccept(buffer);
    }
    else
    {
        Segment seg(buffer.data() + inetHdr->ihl * 4, sizeof(tcphdr));
        tcphdr th = {0};
        th.seq = htonl(seg.ackSeq());
        th.ack_seq = htonl(seg.seq() + 1);
        th.ack = 1;
        th.rst = 1;
        impl_->calcTcpAndSend(pair, th, sizeof(tcphdr));
    }
}

void Tcp::worker(std::future<bool> stop)
{
    printf("Tcp start running.\n");
    while (stop.wait_for(std::chrono::milliseconds(1)) != std::future_status::ready)
    {
        impl_->processTimer();
        std::vector<uint8_t> buffer(1500);
        int nread = impl_->netDev->recv(buffer.data(), buffer.size());
        if (nread < 0)
        {
            continue;
        }
        packetProcessing(buffer);
    }
    printf("Tcp stop running.\n");
}

void Tcp::send(std::shared_ptr<Tcb> tcb)
{
    if (!isEstablished(tcb->addr))
    {
        return;
    }
    uint16_t totalLen = tcb->sndQueue.size();
    if (totalLen == 0)
    {
        return;
    }
    //push to restransmit queue
    tcb->rtmixQueue.insert(tcb->rtmixQueue.end(), tcb->sndQueue.begin(), tcb->sndQueue.end());

    uint16_t haveWritten = 0;
    while (haveWritten < totalLen)
    {
        uint16_t segLen = min<uint16_t>(MSS, tcb->sndQueue.size());
        uint8_t *data = new uint8_t[sizeof(tcphdr) + segLen];
        if (data == nullptr)
        {
            perror("malloc");
            exit(1);
        }

        tcphdr *th = (tcphdr *)data;
        uint8_t *payload = data + sizeof(tcphdr);
        setDefaultValueForTcpHeader(tcb, *th);
        th->ack = 1;
        // RfC 1122 4.2.2.2
        // MUST set the PSH bit in the last buffered segment
        if (haveWritten + segLen >= totalLen)
        {
            th->psh = 1;
        }
        memcpy(payload, tcb->sndQueue.data(), segLen);
        tcb->sndQueue.erase(tcb->sndQueue.begin(), tcb->sndQueue.begin() + segLen);
        impl_->calcTcpAndSend(tcb->addr, *th, sizeof(tcphdr) + segLen);

        tcb->snd.nxt += segLen;
        haveWritten += segLen;
    }

    impl_->addRtmixDataTimerIfNotAdd(tcb);
}

void Tcp::closeConnection(std::shared_ptr<ConnectionSock> sock)
{
    if (!isEstablished(sock->name()))
    {
        return;
    }
    auto tcb = sock->tcb();
    std::lock_guard<std::mutex> lock(tcb->lock);
    switch (tcb->state)
    {
    case TcpState::ESTABLISHED:
        tcb->state = TcpState::FIN_WAIT1;
        break;
    case TcpState::CLOSE_WAIT:
        tcb->state = TcpState::LAST_ACK;
    default:
        break;
    }

    impl_->transmitFin(tcb, tcb->snd.nxt);
    impl_->addRtmixDataTimerIfNotAdd(tcb);
    tcb->snd.nxt += 1;
}

void Tcp::connect(std::shared_ptr<ConnectionSock> sock)
{
    auto tcb = sock->tcb();
    tcb->state = TcpState::SYN_SENT;
    addHalfConnection(sock);
    //send syn packet
    impl_->transmitSyn(tcb);
    tcb->snd.nxt += 1;
    tcb->snd.una = tcb->snd.iss;

    //start retmix time, rto not impl now.
    tcb->rto = MIN_RTO;
    tcb->retransmissionTimer.expired = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(tcb->rto);
    tcb->retransmissionTimer.handler = [this, tcb]() {
        this->impl_->transmitSyn(tcb);
    };
    impl_->AddTimer(tcb);
}

uint16_t Tcp::pickARamdonPort()
{
    uint32_t seed = time(nullptr);
    srand(seed);
    uint16_t port;
    while (1)
    {
        port = rand() / 65535;
        if (impl_->setPortifNotSet(port))
            break;
    }
    return port;
}