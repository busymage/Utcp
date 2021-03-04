#include <Protocol/ChecksumCalc.hpp>
#include <arpa/inet.h>
#include <string.h>

uint32_t sum_every_16bits(void *addr, int count)
{
    register uint32_t sum = 0;
    uint16_t * ptr = (uint16_t*)addr;
    
    while( count > 1 )  {
        /*  This is the inner loop */
        sum += * ptr++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if( count > 0 )
        sum += * (uint8_t *) ptr;

    return sum;
}

uint16_t checksum(void *addr, int count, int start_sum)
{
    /* Compute Internet Checksum for "count" bytes
     *         beginning at location "addr".
     * Taken from https://tools.ietf.org/html/rfc1071
     */
    uint32_t sum = start_sum;

    sum += sum_every_16bits(addr, count);
    
    /*  Fold 32-bit sum to 16 bits */
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

uint16_t caclTcpChecksum(void *addr, int count, uint32_t saddr, uint32_t daddr)
{
    uint8_t *checkData = new uint8_t[sizeof(PsdHdr) + count];
    PsdHdr *psdh = (PsdHdr*)checkData;
    psdh->saddr = saddr;
    psdh->daddr = daddr;
    psdh->zero = 0;
    psdh->pctl = 0x06;
    psdh->tcpLen = htons(count);
    memcpy(checkData + sizeof(PsdHdr), addr, count);
    uint16_t check =  checksum(checkData, sizeof(PsdHdr) + count, 0);
    delete []checkData;
    return check;
}