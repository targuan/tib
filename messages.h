/* 
 * File:   messages.h
 * Author: agrapartth
 *
 * Created on 2 février 2015, 12:06
 */

#ifndef MESSAGES_H
#define	MESSAGES_H

#include <stdint.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct message_occurence_s {
    uint32_t frame_id;
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint16_t vlan;
} message_occurence_t;

typedef struct message_s {
    uint32_t id;
    uint32_t seen;
    message_occurence_t *occurences;
}message_t;


#ifdef	__cplusplus
}
#endif

#endif	/* MESSAGES_H */

