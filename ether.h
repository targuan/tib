/* 
 * File:   ether.h
 * Author: agrapartth
 *
 * Created on 2 février 2015, 10:50
 */

#ifndef ETHER_H
#define	ETHER_H

#include <stdint.h>
#include "utils.h"

#define	ETHER_ADDR_LEN 6
#define DOT1Q_MASK 0xfff
#define DOT1Q_VLAN(x) (ntohs(((dot1q_hdr_t*)x)->flag) & DOT1Q_MASK)

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct ether_addr_s {
    char octet[ETHER_ADDR_LEN] ;
} ether_addr_t;

typedef struct ether_hdr_s {
    ether_addr_t dst;
    ether_addr_t src;
    uint16_t type;
} ether_hdr_t;

typedef struct dot1q_hdr_s {
    uint16_t flag;
    uint16_t type;
} dot1q_hdr_t;

void ether_addr_to_string(ether_addr_t *addr,char * string);

#ifdef	__cplusplus
}
#endif

#endif	/* ETHER_H */

