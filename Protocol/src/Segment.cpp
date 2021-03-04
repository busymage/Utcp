#include <Protocol/Segment.hpp>
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/tcp.h>

struct Segment::Impl
{
    tcphdr *rawData = nullptr;
    uint16_t totalLen = 0;
};

Segment::Segment(const uint8_t *buffer, uint16_t len)
:impl_(new Impl)
{
    assert(buffer != nullptr);
    assert(len >= 20);
    impl_->rawData = (tcphdr*)buffer;
    impl_->totalLen = len;
}

Segment::~Segment() = default;

uint16_t Segment::sport()
{
    return ntohs(impl_->rawData->source);
}

uint16_t Segment::dport()
{
    return ntohs(impl_->rawData->dest);
}

uint32_t Segment::seq()
{
    return ntohl(impl_->rawData->seq);
}

uint32_t Segment::ackSeq()
{
    return ntohl(impl_->rawData->ack_seq);
}

uint8_t Segment::dataOffset()
{
    return impl_->rawData->doff * 4;
}
bool Segment::urg()
{
    return impl_->rawData->urg;
}

bool Segment::ack()
{
    return impl_->rawData->ack;
}

bool Segment::psh()
{
    return impl_->rawData->psh;
}

bool Segment::rst()
{
    return impl_->rawData->rst;
}

bool Segment::syn()
{
    return impl_->rawData->syn;
}

bool Segment::fin()
{
    return impl_->rawData->fin;
}

uint16_t Segment::wnd()
{
    return ntohs(impl_->rawData->window);
}

uint16_t Segment::check()
{
    return ntohs(impl_->rawData->check);
}

uint16_t Segment::urgPtr()
{
    return ntohs(impl_->rawData->urg_ptr);
}

std::vector<TcpOption> Segment::options()
{
    std::vector<TcpOption> opts;

    uint8_t hdrLen = dataOffset();
    uint8_t optLen = hdrLen - 20;
    uint8_t *opt = (uint8_t*)impl_->rawData + 20;
    uint8_t *data = (uint8_t*)impl_->rawData + hdrLen;
    while (opt < data)
    {
        uint8_t kind = *opt;
        if(TCPOPT_EOL == kind){
            break;
        } else if(TCPOPT_NOP == kind){
            opt++;
        } else if(TCPOPT_MAXSEG == kind){
            TcpOption to;
            to.type = kind;
            to.len = *++opt;
            uint16_t *data = (uint16_t*)(++opt);
            to.mss = *data;
            data++;
        }

    }
    return opts;
}

uint8_t *Segment::data()
{
    uint8_t doff = dataOffset();
    uint8_t *data = (uint8_t*)impl_->rawData + doff;
    return data;
}

uint16_t Segment::dataLen()
{
    uint8_t doff = dataOffset();
    return impl_->totalLen - doff;
}

uint8_t *Segment::rawData()
{
    return (uint8_t *)impl_->rawData;
}