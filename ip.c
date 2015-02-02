/* 
 * File:   ip.c
 * Author: agrapartth
 *
 * Created on 2 février 2015, 12:11
 */
#include "ip.h"
#include <stdio.h>


void ip_addr_to_string(uint32_t addr,char *string) {
    uint32_t haddr = ntohl(addr);
    
    sprintf(string,"%d.%d.%d.%d",(haddr&0xff000000)>>24
            ,(haddr & 0x00ff0000u) >> 16
            ,(haddr & 0x0000ff00u) >> 8
            ,haddr & 0x000000ffu);
}