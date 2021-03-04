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

std::vector<uint8_t> buildAckPacket(std::shared_ptr<Tcb> tcb, Segment &seg)
{
        tcphdr resTcpHdr = {0};
        resTcpHdr.source = tcb->addr.dport;
        resTcpHdr.dest = tcb->addr.sport;
        resTcpHdr.seq = htonl(tcb->snd.nxt);
        if(seg.dataLen() == 0){
            resTcpHdr.ack_seq = htonl(seg.seq() + 1);
        }else{
            resTcpHdr.ack_seq = htonl(seg.seq() + seg.dataLen());
        }
        resTcpHdr.doff = 5;
        resTcpHdr.ack = 1;
        resTcpHdr.window = htons(tcb->rcv.wnd);
        resTcpHdr.check = caclTcpChecksum(&resTcpHdr, 20, tcb->addr.daddr, tcb->addr.saddr);

        PacketBuilder pktBuilder(tcb->addr.daddr, tcb->addr.saddr,
                                    &resTcpHdr, 20);
        return pktBuilder.packet();
}

std::vector<uint8_t> buildFinPacket(std::shared_ptr<Tcb> tcb, Segment &seg)
{
        tcphdr resTcpHdr = {0};
        resTcpHdr.source = tcb->addr.dport;
        resTcpHdr.dest = tcb->addr.sport;
        resTcpHdr.seq = htonl(tcb->snd.nxt);
        resTcpHdr.ack_seq = htonl(seg.seq() + 1);
        resTcpHdr.doff = 5;
        resTcpHdr.fin = 1;
        resTcpHdr.ack = 1;
        resTcpHdr.window = htons(RecvWnd);
        resTcpHdr.check = caclTcpChecksum(&resTcpHdr, 20, tcb->addr.daddr, tcb->addr.saddr);

        PacketBuilder pktBuilder(tcb->addr.daddr, tcb->addr.saddr,
                                    &resTcpHdr, 20);
        return pktBuilder.packet();
}

struct Tcp::Impl
{
    std::shared_ptr<INetDevice> netDev;
    std::map<SocketPair, std::shared_ptr<Tcb>> establishedConnection;
    std::map<uint16_t, std::shared_ptr<PassiveSock>> listener;
   
    void synRecvived(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if(!seg.ack()){
            return;
        }
        tcb->state = TcpState::ESTABLISHED;
    }

    void established(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        if(!seg.ack()){
            return;
        }
        //peer close
        if (seg.fin())
        {
            tcb->state = TcpState::CLOSE_WAIT;
            tcphdr resTcpHdr = {0};
            resTcpHdr.source = tcb->addr.dport;
            resTcpHdr.dest = tcb->addr.sport;
            resTcpHdr.seq = htonl(tcb->snd.nxt);
            resTcpHdr.ack_seq = htonl(seg.seq() + 1);
            resTcpHdr.doff = 5;
            resTcpHdr.ack = 1;
            resTcpHdr.window = htons(RecvWnd);
            resTcpHdr.check = caclTcpChecksum(&resTcpHdr, 20, tcb->addr.daddr, tcb->addr.saddr);

            PacketBuilder pktBuilder(tcb->addr.daddr, tcb->addr.saddr,
                                     &resTcpHdr, 20);
            std::vector<uint8_t> outBuffer = pktBuilder.packet();

            size_t nwrite = netDev->send(outBuffer.data(), outBuffer.size());
            if (nwrite == -1)
            {
                perror("write to netDevice:");
                exit(1);
            }
            printf("write %zu bytes\n", nwrite);
            outBuffer.clear();
            
            tcb->state = TcpState::LAST_ACK;
            resTcpHdr.fin = 1;
            resTcpHdr.check = 0;
            resTcpHdr.check = caclTcpChecksum(&resTcpHdr, 20, tcb->addr.daddr, tcb->addr.saddr);

            PacketBuilder pktBuilder1(tcb->addr.daddr, tcb->addr.saddr,
                                     &resTcpHdr, 20);
            outBuffer = pktBuilder1.packet();

            nwrite = netDev->send(outBuffer.data(), outBuffer.size());
            if (nwrite == -1)
            {
                perror("write to netDevice:");
                exit(1);
            }
            printf("write %zu bytes\n", nwrite);

            tcb->snd.una = ntohl(resTcpHdr.seq);
        }
    }

    void close(std::shared_ptr<Tcb> tcb, Segment &seg)
    {
        auto it = establishedConnection.find(tcb->addr);
        establishedConnection.erase(it);
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
    
    if(!seg.ack()){
        return;
    }
    //accpetable ack
    //SND.UNA < SEG.ACK =< SND.NXT
    if(tcb->snd.una >= seg.ackSeq() && tcb->snd.nxt < seg.ackSeq()){
            printf("unacceptable ack.\n");
            return;
    }

    //RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
    if(tcb->rcv.nxt > (seg.seq() + seg.dataLen() - 1) &&
        (tcb->rcv.nxt + tcb->rcv.wnd) <= (seg.seq() + seg.dataLen() - 1)){
            printf("seg not in recv window\n");
            return;
    }
    tcb->rcv.nxt = seg.seq() + seg.dataLen();

    switch (tcb->state)
    {
    case TcpState::SYN_RECEIVED:
        impl_->synRecvived(tcb, seg);
        break;
    case TcpState::ESTABLISHED:
        impl_->established(tcb, seg);
        break;
    case TcpState::LAST_ACK:
        impl_->close(tcb, seg);
    default:
        break;
    }
    std::cout<< *tcb;
}

void Tcp::onAccept(std::vector<uint8_t> &buffer)
{
    if(buffer.size() < 40){
        printf("packet to small\n");
        return;
    }
     
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
        th.ack = 0;
        th.rst = 1;
        th.window = 1234;
        th.check = caclTcpChecksum(&th, 20, 0xa000001, 0xa000002);
        PacketBuilder pb(0xa000001, 0xa000002, &th, 20);
        std::vector<uint8_t> packet = pb.packet();

        int nwrite = impl_->netDev->send(packet.data(), packet.size());
        if(nwrite == -1){
            perror("write to netDevice:");
            exit(1);
        }
        return;
    }
    
    if(!tcpHdr->syn){
        printf("dont have syn\n");
        return;
    }

    // inital tcb
    SocketPair sp = {
        inetHdr->saddr,
        inetHdr->daddr,
        tcpHdr->source,
        tcpHdr->dest
    };
    std::shared_ptr<Tcb> tcb = std::make_shared<Tcb>(sp, tcpHdr);

    tcb->rcv.wnd = RecvWnd;
    tcb->rcv.irs = ntohl(tcpHdr->seq);
    tcb->rcv.nxt = tcpHdr->seq + 1;

    //construct syn,ack handshake
    tcphdr resTcpHdr = {0};
    resTcpHdr.source = tcpHdr->dest;
    resTcpHdr.dest = tcpHdr->source;
    resTcpHdr.seq = tcb->snd.iss;
    resTcpHdr.ack_seq = htonl(tcb->rcv.irs + 1);
    resTcpHdr.doff = 5;
    resTcpHdr.ack = 1;  
    resTcpHdr.syn = 1; 
    resTcpHdr.window = htons(RecvWnd);
    resTcpHdr.check = caclTcpChecksum(&resTcpHdr, 20, inetHdr->daddr, inetHdr->saddr);

    PacketBuilder pktBuilder(inetHdr->daddr, inetHdr->saddr,
                            &resTcpHdr, 20);
    std::vector<uint8_t> outBuffer = pktBuilder.packet();
    
    //update tcb
    tcb->snd.nxt = tcb->snd.iss + 1;
    tcb->snd.una = tcb->snd.iss;
    tcb->state = TcpState::SYN_RECEIVED;

    size_t nwrite =impl_->netDev->send(outBuffer.data(), outBuffer.size());
    if(nwrite == -1){
        perror("write to netDevice:");
        exit(1);
    }
    printf("write %zu bytes\n", nwrite);
    std::cout<< *tcb;

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

void Tcp::packetProcessing(std::vector<uint8_t> &buffer)
{

		iphdr *inetHdr = (iphdr*)buffer.data();
		if(inetHdr->version != 4){
        return;
		}
		if(inetHdr->protocol != 0x06){
        return;
		}
		tcphdr *tcpHdr = (tcphdr*)(buffer.data() + inetHdr->ihl * 4);
		
		SocketPair pair = {
			inetHdr->saddr,
			inetHdr->daddr,
			tcpHdr->source,
			tcpHdr->dest
		};
		
		if(isEstablished(pair)){
			std::shared_ptr<Tcb> tcb = getEstablishedConnection(pair);
			onPacket(tcb, buffer);
    } else if(hasBoundPort(ntohs(tcpHdr->dest))){
			onAccept(buffer);
		} else{
			onAccept(buffer);
		}
	}
}