#ifndef UTCP_SEGMENT_HPP
#define UTCP_SEGMENT_HPP

#include <memory>
#include <stdint.h>
#include <vector>

using TcpOptionType = uint8_t;

struct TcpOption{
    TcpOptionType type;
    uint8_t len;
    union
    {
        uint16_t mss;
    };
    
};

class Segment
{
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
public:
    Segment(const uint8_t *buffer, uint16_t len);
    ~Segment();

    uint16_t sport();
    uint16_t dport();
    uint32_t seq();
    uint32_t ackSeq();
    uint8_t dataOffset();
    bool urg();
    bool ack();
    bool psh();
    bool rst();
    bool syn();
    bool fin();
    uint16_t wnd();
    uint16_t check();
    uint16_t urgPtr();
    std::vector<TcpOption> options();
    
    uint8_t *data();
    uint16_t dataLen();

    uint8_t* rawData();
};

#endif