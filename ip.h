/* 
 * File:   ip.h
 * Author: agrapartth
 *
 * Created on 2 février 2015, 10:50
 */

#ifndef IP_H
#define	IP_H

#include <stdint.h>

#define IP_IHL(x) (is_big_endian()?((x->version_ihl&0xf0) >> 4):(x->version_ihl&0xf))
#define IP_VERSION(x) (is_big_endian()?(x->version_ihl&0xf):((x->version_ihl&0xf0) >> 4))

#ifdef	__cplusplus
extern "C" {
#endif


typedef struct ip_hdr_s {
        uint8_t    version_ihl;
        uint8_t    tos;
        uint16_t   tot_len;
        uint16_t   id;
        uint16_t   frag_off;
        uint8_t    ttl;
        uint8_t    protocol;
        uint16_t   check;
        uint32_t   saddr;
        uint32_t   daddr;
} ip_hdr_t;
void ip_addr_to_string(uint32_t addr,char *string);

#ifdef	__cplusplus
}
#endif

#endif	/* IP_H */

