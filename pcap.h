/* 
 * File:   pcap.h
 * Author: targuan
 *
 * Created on 30 janvier 2015, 19:26
 */

#ifndef PCAP_H
#define	PCAP_H
#include <stdint.h>
#include <stdio.h>



#ifdef	__cplusplus
extern "C" {
#endif

typedef struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

int pcap_open_write_file(FILE **fp,char *filename);
int pcap_open_read_file(FILE **fp,char *filename);
int pcap_read_headers(pcap_hdr_t* header,FILE *fp);
int pcap_read_packet(pcaprec_hdr_t *header,void *buffer,FILE *fp);

int pcap_close_file(FILE *fp);


#ifdef	__cplusplus
}
#endif

#endif	/* PCAP_H */

