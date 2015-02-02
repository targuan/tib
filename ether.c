#include "ether.h"
#include <stdio.h>

void ether_addr_to_string(ether_addr_t *addr,char * string) {
    sprintf(string,"%02x:%02x:%02x:%02x:%02x:%02x",addr->octet[0]& 0xff
            ,addr->octet[1]& 0xff
            ,addr->octet[2]& 0xff
            ,addr->octet[3]& 0xff
            ,addr->octet[4]& 0xff
            ,addr->octet[5]& 0xff);
}