/* 
 * File:   utils.h
 * Author: agrapartth
 *
 * Created on 2 février 2015, 12:05
 */

#ifndef UTILS_H
#define	UTILS_H

#include <stdint.h>

#define BUFFER_SIZE 4096

#define MAX(a,b) (a>b?a:b)
#define MIN(a,b) (a<b?a:b)

#ifdef	__cplusplus
extern "C" {
#endif


int is_big_endian(void);
uint16_t ntohs(uint16_t x);
uint16_t htons(uint16_t x);
uint32_t ntohl(uint32_t x);
uint32_t htonl(uint32_t x);


#ifdef	__cplusplus
}
#endif

#endif	/* UTILS_H */

