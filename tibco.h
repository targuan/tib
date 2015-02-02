/* 
 * File:   tibco.h
 * Author: agrapartth
 *
 * Created on 2 février 2015, 12:04
 */

#ifndef TIBCO_H
#define	TIBCO_H

#include <stdint.h>


#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dark_hdr_s {
    char black1[20];
    uint32_t id;
} dark_hdr_t;


#ifdef	__cplusplus
}
#endif

#endif	/* TIBCO_H */

