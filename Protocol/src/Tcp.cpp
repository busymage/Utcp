#include <Protocol/PacketBuilder.hpp>
#include <Protocol/ChecksumCalc.hpp>
#include <Protocol/INetDevice.hpp>
#include <Protocol/Segment.hpp>
#include <Protocol/SocketPair.hpp>
#include <Protocol/Tcb.hpp>
#include <Protocol/Tcp.hpp>
#include <iostream>
#include <map>
#include <memory>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>

constexpr const uint16_t RecvWnd = 65535;

struct ConnectionSock{
    std::vector<char> sendBuffer;
    std::vector<char> recvBuffer;
};

struct PassiveSock{
    //pid_t process;
    uint16_t port;
    std::vector<ConnectionSock> backlog;
};

void setDefaultValueForTcpHeader(std::shared_ptr<Tcb> tcb, tcphdr &th)
{
    th.source = tcb->addr.dport;
    th.dest = tcb->addr.sport;
    th.seq = htonl(tcb->snd.nxt);
    th.ack_seq = htonl(tcb->rcv.nxt);
    th.doff = 5;
    th.window = htons(tcb->rcv.wnd);
}

std::vector<uint8_t> buildAckPacket(std::shared_ptr<Tcb> tcb, uint32_t ack_seq)
{
    tcphdr resTcpHdr = {0};
    setDefaultValueForTcpHeader(tcb, resTcpHdr);
    resTcpHdr.ack_seq = htonl(ack_seq);
    resTcpHdr.ack = 1;
    resTcpHdr.check = caclTcpChecksum(&resTcpHdr, 20, tcb->addr.daddr, tcb->addr.saddr);
    PacketBuilder pktBuilder(tcb->addr.daddr, tcb->addr.saddr,
                                &resTcpHdr, 20);
    return pktBuilder.packet();
}

std::vector<uint8_t> buildRstPacket(std::shared_ptr<Tcb> tcb)
{
        tcphdr resTcpHdr = {0};
        setDefaultValueForTcpHeader(tcb, resTcpHdr);
        resTcpHdr.rst = 1;
        resTcpHdr.check = caclTcpChecksum(&resTcpHdr, 20, tcb->addr.daddr, tcb->addr.saddr);
        PacketBuilder pktBuilder(tcb->addr.daddr, tcb->addr.saddr,
                                    &resTcpHdr, 20);
        return pktBuilder.packet();
}

bool isBetween(uint32_t seq, uint32_t start, uint32_t end)
{   
    //should care about warpping.
    return seq >= start && seq < end;
}

struct Tcp::Impl
{
    std::shared_ptr<INetDevice> netDev;
    std::map<SocketPair, std::shared_ptr<Tcb>> establishedConnection;
    std::map<uint16_t, std::shared_ptr<PassiveSock>> listener;

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
   
    bool synRecvived(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        //SND.UNA =< SEG.ACK =< SND.NXT
        if(seg.ackSeq() < tcb->snd.una ||
           seg.ackSeq() > tcb->snd.nxt){
            tcphdr th = {0};
            setDefaultValueForTcpHeader(tcb, th);
            th.seq = htonl(seg.ackSeq());
            th.rst = 1;
            th.check = caclTcpChecksum(&th, 20, tcb->addr.daddr, tcb->addr.saddr);
            PacketBuilder pktBuilder(tcb->addr.daddr, tcb->addr.saddr,
                                    &th, 20);
            auto outBuffer = pktBuilder.packet();
            netDev->send(outBuffer.data(), outBuffer.size());
            auto it = establishedConnection.find(tcb->addr);
            establishedConnection.erase(it);
            return false;
        }
        tcb->state = TcpState::ESTABLISHED;
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
            receiveData(tcb, seg);
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
            return false;
        }
        else if(seg.ackSeq() > tcb->snd.nxt){
            auto OutBuffer = buildAckPacket(tcb, seg.seq());
            netDev->send(OutBuffer.data(), OutBuffer.size());
            return false;
        }
        return false;
    }

    void receiveData(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        uint8_t *data = seg.data();
        uint16_t minSize = seg.dataLen() >= tcb->rcv.wnd ? tcb->rcv.wnd : seg.dataLen();
        tcb->recvQueue.insert(tcb->recvQueue.end(), data, data + minSize);
        tcb->rcv.nxt += minSize;
        tcb->rcv.wnd -= minSize; 
    }

    void sendAcknowledgment(std::shared_ptr<Tcb> tcb)
    {
        auto Outbuffer = buildAckPacket(tcb, tcb->rcv.nxt);
        netDev->send(Outbuffer.data(), Outbuffer.size());
    }
};

Tcp::Tcp(std::shared_ptr<INetDevice> netDev)
    : impl_(new Impl)
{
    impl_->netDev = netDev;
}

Tcp::~Tcp() = default;

bool Tcp::isEstablished(SocketPair &pair)const
{
    return  impl_->establishedConnection.find(pair) != impl_->establishedConnection.end();
}

std::shared_ptr<Tcb> &Tcp::getEstablishedConnection(SocketPair &pair)
{
    return impl_->establishedConnection[pair];
}

bool Tcp::hasBoundPort(uint16_t port) const
{
    return impl_->listener.find(port) != impl_->listener.end();
}

void Tcp::onPacket(std::shared_ptr<Tcb> tcb, std::vector<uint8_t> &buffer)
{
    iphdr *ih = (iphdr*)buffer.data();
    Segment seg(buffer.data() + ih->ihl * 4, ntohs(ih->tot_len) - ih->ihl * 4);
    
    //step1
    if(!impl_->checkSequenceNumber(tcb, seg)){
        if(seg.rst()){
            return;
        }
        std::vector<uint8_t> outBuffer = buildAckPacket(tcb, tcb->rcv.nxt);
        impl_->netDev->send(outBuffer.data(), outBuffer.size());
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
            case TcpState::SYN_SENT:
            //Todo
                break;
            case TcpState::ESTABLISHED:
            case TcpState::FIN_WAIT1:
            case TcpState::FIN_WAIT2:
            case TcpState::CLOSE_WAIT:
            //Todo
                break;
            case TcpState::CLOSING:
            case TcpState::LAST_ACK:
            case TcpState::TIME_WAIT:
            //Todo
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
        th.check = caclTcpChecksum(&th, 20, 0xa000001, 0xa000002);
        PacketBuilder pb(0xa000001, 0xa000002, &th, 20);
        std::vector<uint8_t> packet = pb.packet();
        impl_->netDev->send(packet.data(), packet.size());
        return;
    }
    
    if(!tcpHdr->syn){
        printf("dont have syn\n");
        return;
    }

    // inital tcb
    SocketPair sp = {
        inetHdr->saddr,
        tcpHdr->source,
        inetHdr->daddr,
        tcpHdr->dest
    };
    std::shared_ptr<Tcb> tcb = std::make_shared<Tcb>(sp, tcpHdr);

    //construct syn,ack handshake
    tcphdr resTcpHdr = {0};
    setDefaultValueForTcpHeader(tcb, resTcpHdr);
    resTcpHdr.seq = htonl(tcb->snd.iss);
    resTcpHdr.ack = 1;  
    resTcpHdr.syn = 1; 
    resTcpHdr.check = caclTcpChecksum(&resTcpHdr, 20, inetHdr->daddr, inetHdr->saddr);

    PacketBuilder pktBuilder(inetHdr->daddr, inetHdr->saddr,
                            &resTcpHdr, 20);
    std::vector<uint8_t> outBuffer = pktBuilder.packet();
    
    impl_->netDev->send(outBuffer.data(), outBuffer.size());
    
    //update tcb
    tcb->snd.nxt = tcb->snd.iss + 1;
    tcb->snd.una = tcb->snd.iss;
    tcb->state = TcpState::SYN_RECEIVED;

    //add tcb to map
    impl_->establishedConnection[tcb->addr] = tcb;
}

void Tcp::run()
{
    while (1)
	{
		std::vector<uint8_t> buffer(1500);
		int nread = impl_->netDev->recv(buffer.data(), buffer.size());
		if (nread < 0)
		{
			perror("Reading from interface");
			exit(1);
		}
		printf("got %d bytes\n", nread);
	}
}
		
bool Tcp::addListener(uint16_t port)
{
    if(impl_->listener.find(port) != impl_->listener.end()){
        return false;
    }
    std::shared_ptr<PassiveSock> ps = std::make_shared<PassiveSock>();
    ps->port = port;
    impl_->listener[port] = ps;
    return true;
}

bool Tcp::addConnection(std::shared_ptr<Tcb> tcb)
{
    if(impl_->establishedConnection.find(tcb->addr) != impl_->establishedConnection.end()){
        return false;
    }
    impl_->establishedConnection[tcb->addr] = tcb;
    return true;
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

    SocketPair pair = {
        inetHdr->saddr,
        tcpHdr->source,
        inetHdr->daddr,
        tcpHdr->dest};

    if (isEstablished(pair))
    {
        std::shared_ptr<Tcb> tcb = getEstablishedConnection(pair);
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