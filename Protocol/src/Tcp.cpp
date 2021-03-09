#include <Protocol/PacketBuilder.hpp>
#include <Protocol/ChecksumCalc.hpp>
#include <Protocol/ConnectionSock.hpp>
#include <Protocol/INetDevice.hpp>
#include <Protocol/PassiveSock.hpp>
#include <Protocol/Segment.hpp>
#include <Protocol/SocketPair.hpp>
#include <Protocol/Tcb.hpp>
#include <Protocol/Tcp.hpp>
#include <chrono>
#include <future>
#include <iostream>
#include <map>
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
    uint8_t *start = (uint8_t*)&addr;
    for (int i = 0; i < 4; i++)
    {
        str += std::to_string(start[i]);
        if(i < 3){
            str += '.';
        }
    }
    return str;
}

void printTcphdrInfo(uint32_t saddr, uint32_t daddr, tcphdr &th)
{
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

template<typename T>
T min(T lhs, T rhs)
{
    return lhs <= rhs ? lhs : rhs;
}

struct Tcp::Impl
{
    std::shared_ptr<INetDevice> netDev;
    
    std::map<SocketPair, std::shared_ptr<ConnectionSock>> establishedConnection;
    
    std::map<uint16_t, std::shared_ptr<PassiveSock>> listener;

    bool start = false;

    std::thread workerThread;

    //stop signal
    std::promise<bool> stop;

    bool checkSequenceNumber(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if(tcb->rcv.wnd == 0){
            //<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            //SEG.SEQ = RCV.NXT 
            if(seg.dataLen() > 0 || seg.seq() != tcb->rcv.nxt){
                return false;
            }
        }
        //RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        if(!isBetween(seg.seq(), tcb->rcv.nxt, tcb->rcv.nxt + tcb->rcv.wnd)){
            return false;
        }
        return true;
    }

    void synSent(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if(seg.ackSeq() <= tcb->snd.iss || seg.ackSeq() > tcb->snd.nxt){
            if(!seg.rst()){
                sendAckErrorReset(tcb, seg.ackSeq());
            }
            return;
        }
        if(tcb->snd.una > seg.ackSeq() && seg.ackSeq() > tcb->snd.nxt){
            return;
        }
        if(seg.rst()){
            //notify user
            deleteTcb(tcb);
        }
        if(seg.syn()){
            if(seg.ack() || (!seg.rst() && !seg.ack())){
                tcb->rcv.nxt = seg.seq() + 1;
                tcb->rcv.irs = seg.seq();
                if(seg.ack()){
                    tcb->snd.una = seg.ackSeq();
                    //clear retransmission queue
                }
                if(tcb->snd.una > tcb->snd.iss){
                    tcb->state = TcpState::ESTABLISHED;
                    sendAcknowledgment(tcb);
                }else{
                    tcb->state = TcpState::SYN_RECEIVED;
                    tcphdr th = {0};
                    setDefaultValueForTcpHeader(tcb, th);
                    th.seq = tcb->snd.iss;
                    th.syn = 1;
                    th.ack = 1;
                    calcTcpAndSend(tcb, th);
                }
            }
        }
    }
   
    bool synRecvived(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        //SND.UNA =< SEG.ACK =< SND.NXT
        if(seg.ackSeq() < tcb->snd.una ||
           seg.ackSeq() > tcb->snd.nxt){
            tcphdr th = {0};
            setDefaultValueForTcpHeader(tcb, th);
            th.seq = htonl(seg.ackSeq());
            th.rst = 1;
            calcTcpAndSend(tcb, th);
            auto it = establishedConnection.find(tcb->addr);
            establishedConnection.erase(it);
            return false;
        }
        tcb->state = TcpState::ESTABLISHED;
        //add sock to backlog
        auto connection = establishedConnection[tcb->addr];
        auto accpetor = listener[tcb->addr.sport];
        accpetor->acceptSock(connection);

        if(seg.fin()){
            tcb->rcv.nxt = seg.seq() + 1;
            sendAcknowledgment(tcb);
            tcb->state = TcpState::CLOSE_WAIT;
        }
        return true;
    }

    bool established(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if(!handleAck(tcb, seg)){
            return false;
        }
        if(seg.dataLen() > 0){
            auto conn = establishedConnection[tcb->addr];
            receiveData(conn, seg);
        }
        if(seg.fin()){
            tcb->rcv.nxt = seg.seq() + 1;
            tcb->state = TcpState::CLOSE_WAIT;
        }
        sendAcknowledgment(tcb);
        return true;
    }

    bool lastAck(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if(!handleAck(tcb, seg)){
            return false;
        }
        if(seg.fin()){
            tcb->rcv.nxt = seg.seq() + 1;
            sendAcknowledgment(tcb);
        }
        auto it = establishedConnection.find(tcb->addr);
        establishedConnection.erase(it);
        return true;
    }

    bool finWait1(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if(!handleAck(tcb, seg)){
            return false;
        }
        if(seg.ackSeq() == tcb->snd.nxt){
            tcb->state = TcpState::FIN_WAIT2;
        }
        if(seg.dataLen() > 0){
            sendAcknowledgment(tcb);
        }
        //Simultaneous Close
        if(seg.fin()){
            tcb->rcv.nxt = 1 + seg.seq(); 
            sendAcknowledgment(tcb);
            if(tcb->state == TcpState::FIN_WAIT2){
                tcb->state = TcpState::TIME_WAIT;
            }else{
                tcb->state = TcpState::CLOSING;
            }
            return true;
        }
        return true;
    }

    bool finWait2(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if(!handleAck(tcb, seg)){
            return false;
        }
        if(seg.dataLen() > 0){
            sendAcknowledgment(tcb);
        }
        if(seg.fin()){
            tcb->state = TcpState::TIME_WAIT;
            tcb->rcv.nxt = seg.seq() + 1;
            sendAcknowledgment(tcb);
        }
        return true;

    }

    bool closeWait(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if(!handleAck(tcb, seg)){
            return false;
        }
        if(seg.fin()){
            tcb->rcv.nxt = seg.seq() + 1;
            sendAcknowledgment(tcb);
        }
        return true;
    }

    bool closing(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if(!handleAck(tcb, seg)){
            return false;
        }
        //if the ACK acknowledges our FIN then enter the TIME-WAIT state,
        //otherwise ignore the segment.
        if(seg.ackSeq() == tcb->snd.nxt){
            tcb->state = TcpState::TIME_WAIT;
        }
        if(seg.fin()){
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
        if(seg.fin()){
            tcb->rcv.nxt = seg.seq() + 1;
            sendAcknowledgment(tcb);
        }
        return true;
    }

    bool handleAck(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        //SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
        if (tcb->snd.una < seg.ackSeq() && seg.ackSeq() <= tcb->snd.nxt){
            tcb->snd.una = seg.ackSeq();
            //remove retransmission queue
            //update send window
            if (tcb->snd.wl1 <= seg.seq() && tcb->snd.wl2 <= seg.ackSeq())
            {
                tcb->snd.wnd = seg.wnd();
                tcb->snd.wl1 = seg.seq();
                tcb->snd.wl2 = seg.ackSeq();
            }
            return true;
        }
        else if (seg.ackSeq() < tcb->snd.una){
            //ingore
            return true;
        }
        else if(seg.ackSeq() > tcb->snd.nxt){
            auto th = buildAckSegment(tcb, seg.seq());
            sendPacket(tcb, th);
            return false;
        }
        return true;
    }

    void receiveData(std::shared_ptr<ConnectionSock> sock, Segment &seg)
    {
        auto tcb = sock->tcb();
        uint8_t *data = seg.data();
        uint16_t minSize = seg.dataLen() >= tcb->rcv.wnd ? tcb->rcv.wnd : seg.dataLen();
        sock->RecvFromTcp(data, minSize);  
        tcb->rcv.nxt += minSize;
        tcb->rcv.wnd -= minSize; 
    }

    void sendAcknowledgment(std::shared_ptr<Tcb> tcb)
    {
        auto th = buildAckSegment(tcb, tcb->rcv.nxt);
        sendPacket(tcb, th);
    }

    void sendAckErrorReset(std::shared_ptr<Tcb> tcb, uint32_t ack)
    {
        tcphdr th = {0};
        setDefaultValueForTcpHeader(tcb, th);
        th.seq = htonl(ack);
        th.rst = 1;
        calcTcpAndSend(tcb, th);
    }

    void deleteTcb(std::shared_ptr<Tcb> tcb){
        auto it = establishedConnection.find(tcb->addr);
        establishedConnection.erase(it);
    }

    void calcTcpAndSend(std::shared_ptr<Tcb> tcb, tcphdr &th){
        th.check = caclTcpChecksum(&th, 20, tcb->addr.saddr, tcb->addr.daddr);
        sendPacket(tcb,th);
    }

    void sendPacket(std::shared_ptr<Tcb> tcb, tcphdr &th)
    {
        printf("Send ");
        printTcphdrInfo(tcb->addr.saddr, tcb->addr.daddr, th);
        PacketBuilder pktBuilder(tcb->addr.saddr, tcb->addr.daddr,&th, 20);
        auto outBuffer = pktBuilder.packet();
        netDev->send(outBuffer.data(), outBuffer.size());
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
    if(impl_->workerThread.joinable()){
        impl_->workerThread.join();
    }

    //remove all all sock tcp holds.
    impl_->listener.clear();
    impl_->establishedConnection.clear();
}

bool Tcp::isEstablished(SocketPair &pair)const
{
    return  impl_->establishedConnection.find(pair) != impl_->establishedConnection.end();
}

std::shared_ptr<ConnectionSock> Tcp::getEstablishedConnection(SocketPair &pair)
{
    if(isEstablished(pair)){
    return impl_->establishedConnection[pair];
}
    return {};
}

bool Tcp::hasBoundPort(uint16_t port) const
{
    return impl_->listener.find(htons(port)) != impl_->listener.end();
}

void Tcp::onPacket(std::shared_ptr<Tcb> tcb, std::vector<uint8_t> &buffer)
{
    iphdr *ih = (iphdr*)buffer.data();
    Segment seg(buffer.data() + ih->ihl * 4, ntohs(ih->tot_len) - ih->ihl * 4);

    if(tcb->state == TcpState::SYN_SENT){
        impl_->synSent(tcb, seg);
        return;
    }
    
    //step1
    if(!impl_->checkSequenceNumber(tcb, seg)){
        if(seg.rst()){
            return;
        }
        auto th = buildAckSegment(tcb, tcb->rcv.nxt);
        impl_->sendPacket(tcb, th);
        return;
    }

    //step2
    if(seg.rst()){
        switch (tcb->state){
            case TcpState::SYN_RECEIVED:
            {
            auto it = impl_->establishedConnection.find(tcb->addr);
            impl_->establishedConnection.erase(it);
            return;
            }
            case TcpState::ESTABLISHED:
            case TcpState::FIN_WAIT1:
            case TcpState::FIN_WAIT2:
            case TcpState::CLOSE_WAIT:
            //Todo
                impl_->deleteTcb(tcb);
                break;
            case TcpState::CLOSING:
            case TcpState::LAST_ACK:
            case TcpState::TIME_WAIT:
            //Todo
                impl_->deleteTcb(tcb);
                break;
            default:
                return;
        }
    }

    //step4
    if(seg.syn()){
        if(tcb->isSynchronizedState()){
            auto outBuffer = buildRstPacket(tcb);
            impl_->netDev->send(outBuffer.data(), outBuffer.size());
            auto it = impl_->establishedConnection.find(tcb->addr);
            impl_->establishedConnection.erase(it);
        }
        return;
    }

    if(!seg.ack()){
        return;
    }
    
    //step5
    switch (tcb->state)
    {
    case TcpState::SYN_RECEIVED:
        if(!impl_->synRecvived(tcb, seg)){
            return;
        }
        break;
    case TcpState::ESTABLISHED:
        if(!impl_->established(tcb, seg)){
            return;
        }
        break;
    case TcpState::LAST_ACK:
        if(impl_->lastAck(tcb, seg)){
            return;
        }
        break;
    case TcpState::FIN_WAIT1:
        if(!impl_->finWait1(tcb, seg)){
            return;
        }
        break;
    case TcpState::FIN_WAIT2:
        if(!impl_->finWait2(tcb, seg)){
            return;
        }
        break;
    case TcpState::CLOSE_WAIT:
        if(!impl_->closeWait(tcb, seg)){
            return;
        }
        break;
    case TcpState::CLOSING:
        if(!impl_->closing(tcb, seg)){
            return;
        }
        break;
    case TcpState::TIME_WAIT:
        if(!impl_->timeWait(tcb, seg)){
            return;
        }
        break;
    default:
        break;
    }
}

void Tcp::onAccept(std::vector<uint8_t> &buffer)
{ 
    iphdr *inetHdr = (iphdr*)buffer.data();
    tcphdr *tcpHdr = (tcphdr*)(buffer.data() + inetHdr->ihl * 4);
    
    //first check for an RST An incoming RST should be ignored.  Return.
    if(tcpHdr->rst){
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
    if (tcpHdr->ack){
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
        printTcphdrInfo(inetHdr->daddr, inetHdr->saddr, th);
        impl_->netDev->send(packet.data(), packet.size());
        return;
    }
    
    if(!tcpHdr->syn){
        printf("dont have syn\n");
        return;
    }

    // inital tcb
    SocketPair sp = {
        inetHdr->daddr,     //local
        tcpHdr->dest,
        inetHdr->saddr,     //foregin
        tcpHdr->source
    };
    std::shared_ptr<Tcb> tcb = std::make_shared<Tcb>(sp, tcpHdr);

    //construct syn,ack handshake
    tcphdr resTcpHdr = {0};
    setDefaultValueForTcpHeader(tcb, resTcpHdr);
    resTcpHdr.seq = htonl(tcb->snd.iss);
    resTcpHdr.ack = 1;  
    resTcpHdr.syn = 1; 
    resTcpHdr.check = caclTcpChecksum(&resTcpHdr, 20, sp.saddr, sp.daddr);

    PacketBuilder pktBuilder(sp.saddr, sp.daddr,
                            &resTcpHdr, 20);
    std::vector<uint8_t> outBuffer = pktBuilder.packet();
    printTcphdrInfo(sp.saddr, sp.daddr, resTcpHdr);
    impl_->netDev->send(outBuffer.data(), outBuffer.size());
    
    //update tcb
    tcb->snd.nxt = tcb->snd.iss + 1;
    tcb->snd.una = tcb->snd.iss;
    tcb->state = TcpState::SYN_RECEIVED;

    //add connection to map
    impl_->establishedConnection[tcb->addr] = std::make_shared<ConnectionSock>(this, tcb);
}

void Tcp::run()
{
    if(impl_->start){
        return;
    }
    impl_->start = true;
    std::future<bool> stop = impl_->stop.get_future();
    impl_->workerThread = std::thread(&Tcp::worker, this, std::move(stop));
}

void Tcp::stop()
{
    if(impl_->start){
        impl_->stop.set_value(true);
        impl_->start = false;
    }
}
		
bool Tcp::addListener(std::shared_ptr<PassiveSock> sock)
{
    if(impl_->listener.find(sock->name().sport) != impl_->listener.end()){
        return false;
    }
    impl_->listener[sock->name().sport] = sock;
    return true;
}

void Tcp::removeListener(uint16_t port)
{
    auto it = impl_->listener.find(port);
    if(it != impl_->listener.end()){
        impl_->listener.erase(it);
    }
}

bool Tcp::addConnection(std::shared_ptr<ConnectionSock> sock)
{
    if(impl_->establishedConnection.find(sock->name()) != impl_->establishedConnection.end()){
        return false;
    }
    impl_->establishedConnection[sock->name()] = sock;
    return true;
}

void Tcp::removeConnection(SocketPair &sockname)
{
    auto it = impl_->establishedConnection.find(sockname);
    if(it != impl_->establishedConnection.end()){
        impl_->establishedConnection.erase(it);
    }
}

void Tcp::packetProcessing(std::vector<uint8_t> &buffer)
{
    if(buffer.size() < 40){
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
    printf("Recv ");
    printTcphdrInfo(inetHdr->saddr, inetHdr->daddr, *tcpHdr);

    SocketPair pair = {
        inetHdr->daddr,     //local
        tcpHdr->dest,
        inetHdr->saddr,     //foregin
        tcpHdr->source};

    if (isEstablished(pair))
    {
        std::shared_ptr<Tcb> tcb = getEstablishedConnection(pair)->tcb();
        onPacket(tcb, buffer);
    }
    else if (hasBoundPort(ntohs(tcpHdr->dest)))
    {
        onAccept(buffer);
    }
    else
    {
    }
}

void Tcp::worker(std::future<bool> stop)
{
    printf("Tcp start running.\n");
    while (stop.wait_for(std::chrono::milliseconds(1)) != std::future_status::ready)
	{
		std::vector<uint8_t> buffer(1500);
		int nread = impl_->netDev->recv(buffer.data(), buffer.size());
		if (nread < 0)
		{
			perror("Reading from interface");
			exit(1);
		}
		packetProcessing(buffer);
	}
    printf("Tcp stop running.\n");
}

void Tcp::send(std::shared_ptr<Tcb> tcb)
{
    uint16_t totalLen = tcb->sndQueue.size();
    uint16_t haveWritten = 0;
    while (haveWritten < totalLen)
    {
        uint16_t segLen = min<uint16_t>(MSS, tcb->sndQueue.size());      
        uint8_t *data = new uint8_t[sizeof(tcphdr) + segLen];
        if(data == nullptr){
            perror("malloc");
            exit(1);
        }
        tcphdr *th = (tcphdr*)data;
        uint8_t *payload = data + sizeof(tcphdr);
        setDefaultValueForTcpHeader(tcb, *th);
        th->ack = 1;
        memcpy(payload, tcb->sndQueue.data(),segLen);
        tcb->sndQueue.erase(tcb->sndQueue.begin(), tcb->sndQueue.begin() + segLen);
        impl_->calcTcpAndSend(tcb, *th);
        tcb->snd.nxt += segLen;
        haveWritten += segLen;
    }
    
}