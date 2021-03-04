#ifndef UTCP_CHECKSUMCALC_HPP
#define UTCP_CHECKSUMCALC_HPP

#include <stdint.h>

struct PsdHdr{
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t pctl;
    uint16_t tcpLen;
};

uint16_t checksum(void *addr, int count, int start_sum);

uint16_t caclTcpChecksum(void *addr, int count, uint32_t saddr, uint32_t daddr);

#endif