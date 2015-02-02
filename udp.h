/* 
 * File:   udp.h
 * Author: agrapartth
 *
 * Created on 2 février 2015, 10:50
 */

#ifndef UDP_H
#define	UDP_H

#include <stdint.h>

#ifdef	__cplusplus
extern "C" {
#endif


typedef struct udp_hdr_s {
        uint16_t   sport;
        uint16_t   dport;
        uint16_t   len;
        uint16_t   check;
} udp_hdr_t;


#ifdef	__cplusplus
}
#endif

#endif	/* UDP_H */

