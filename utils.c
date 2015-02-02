/* 
 * File:   utils.c
 * Author: agrapartth
 *
 * Created on 2 février 2015, 12:08
 */

#include "utils.h"

int is_big_endian(void)
{
    union {
        uint32_t i;
        char c[4];
    } bint = {0x01020304};

    return bint.c[0] == 1; 
}

uint16_t ntohs(uint16_t x) {
    if(is_big_endian()) return x;
    return ((((x) >> 8) & 0xffu) | (((x) & 0xffu) << 8));
}
uint16_t htons(uint16_t x) {
    return ntohs(x);
}

uint32_t ntohl(uint32_t x) {
    return ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >>  8) | \
            (((x) & 0x0000ff00u) <<  8) | (((x) & 0x000000ffu) << 24));
}

uint32_t htonl(uint32_t x) {
    return ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >>  8) | \
            (((x) & 0x0000ff00u) <<  8) | (((x) & 0x000000ffu) << 24));
}
