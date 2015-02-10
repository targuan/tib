/* 
 * File:   main.c
 * Author: targuan
 *
 * Created on 30 janvier 2015, 19:26
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "utils.h"
#include "Judy.h"

#include "pcap.h"
#include "ether.h"
#include "ip.h"
#include "udp.h"
#include "tibco.h"

#include "messages.h"


#define PARSE_SKIP 0x1
#define PARSE_NO_VLAN 0x2
#define PARSE_IGMP_PACKET 0x4
#define PARSE_LONG_IP_HEADER 0x8
#define PARSE_NOT_UDP 0x10
#define PARSE_SHORT_PACKET 0x20

/*
 */
int parse_packet(pcaprec_hdr_t *header,void * buffer,ether_hdr_t ** ether,dot1q_hdr_t ** dot1q,ip_hdr_t ** ip,udp_hdr_t ** udp,dark_hdr_t ** dark) {
    int ret_val = 0;
    int offset = 0;
    int vlan = 5000;
    char string1[BUFFER_SIZE];
    char string2[BUFFER_SIZE];
    
    dot1q_hdr_t * internal_dot1q;
    
    // Ethernet
    *ether = (ether_hdr_t*) (buffer + offset);
    offset += sizeof (ether_hdr_t);
    if(offset >= header->incl_len) {
        ret_val |= PARSE_SHORT_PACKET|PARSE_SKIP;
        return ret_val;
    }
    
    // DOT1Q
    if (ntohs((*ether)->type) == 0x8100) {
        *dot1q = (dot1q_hdr_t*) (buffer + offset);
        vlan = DOT1Q_VLAN(*dot1q);
        
        internal_dot1q = *dot1q;
        
        while(ntohs(internal_dot1q->type) == 0x8100) {
            offset += sizeof (dot1q_hdr_t);
            internal_dot1q = (dot1q_hdr_t*) (buffer + offset);
        }
        offset += sizeof (dot1q_hdr_t);
        
        if(offset >= header->incl_len) {
            ret_val |= PARSE_SHORT_PACKET|PARSE_SKIP;
            return ret_val;
        }
        
    } else {
        ret_val |= PARSE_NO_VLAN;
    }

    // IP
    *ip = (ip_hdr_t*) (buffer + offset);
    offset += sizeof (ip_hdr_t);
    if(offset >= header->incl_len) {
        ret_val |= PARSE_SHORT_PACKET|PARSE_SKIP;
        return ret_val;
    }

    if (IP_IHL((*ip)) != 5) {
        ip_addr_to_string((*ip)->saddr, string1);
        ip_addr_to_string((*ip)->daddr, string2);

        if((*ip)->protocol == 2) {
            ret_val |= PARSE_IGMP_PACKET|PARSE_SKIP;
            //printf("IHL != 5 (read %d) skipping packet %d from %s to %s on vlan (IGMP packet) \n", IP_IHL((*ip)), frame_id, string1, string2);
        } else {
            ret_val |= PARSE_LONG_IP_HEADER|PARSE_SKIP;
            //printf("IHL != 5 (read %d) skipping packet %d from %s to %s on vlan \n", IP_IHL((*ip)), frame_id, string1, string2);

        }
    }
    if ((*ip)->protocol != 17) {
        ret_val |= PARSE_NOT_UDP|PARSE_SKIP;
    }

    *udp = (udp_hdr_t*) (buffer + offset);
    offset += sizeof (udp_hdr_t);

    *dark = (dark_hdr_t*) (buffer + offset);
    offset += sizeof (dark_hdr_t);
    
    if(offset >= header->incl_len) {
        ret_val |= PARSE_SHORT_PACKET|PARSE_SKIP;
    }
    
    return ret_val;
}

/*
 * 
 */
int main(int argc, char** argv) {
    FILE *fpr, *fpw;
    pcap_hdr_t pcap_hdr;
    pcaprec_hdr_t header;
    char buffer[BUFFER_SIZE];
    char string1[BUFFER_SIZE];
    char string2[BUFFER_SIZE];

    int frame_id = 0;
    int ret_val;

    struct tm * timeinfo;
    
    ether_hdr_t * ether;
    dot1q_hdr_t * dot1q;
    ip_hdr_t * ip;
    udp_hdr_t * udp;
    dark_hdr_t * dark;

    Pvoid_t conversation_array = (Pvoid_t) NULL;
    Pvoid_t src_array = (Pvoid_t) NULL;
    Pvoid_t id_array = (Pvoid_t) NULL;
    
    Pvoid_t save_frame_array = (Pvoid_t) NULL;
    Pvoid_t save_id_array = (Pvoid_t) NULL;

    Word_t Index, Index1, Index2, Index3, Index4;
    Word_t * PValue, *PValue1, *PValue2, *PValue3, *PValue4;
    Word_t count;

    float time;

    message_occurence_t *message_occurence;

    if (argc < 2) {
        printf("No file\n");
        return 1;
    }

    pcap_open_write_file(&fpw,"test.pcap");
    pcap_open_read_file(&fpr, argv[1]);
    if (!fpr) {
        printf("Can't open file\n");
        return 1;
    }

    printf("First Pass\n");
    fflush(stdout);
    
    if (pcap_read_headers(&pcap_hdr, fpr) == 0) {
        while (pcap_read_packet(&header, (void *) buffer, fpr) == 0) {
            frame_id++;
            
            ret_val = parse_packet(&header,buffer,&ether,&dot1q,&ip,&udp,&dark);
            
            
            if(ret_val & PARSE_SKIP) {
                ip_addr_to_string(ip->saddr, string1);
                ip_addr_to_string(ip->daddr, string2);
                printf("Skipping %d from %s to %s vlan %d\n",frame_id,string1,string2,DOT1Q_VLAN(dot1q));
                if(ret_val & PARSE_IGMP_PACKET) {
                    printf("\tIGMP\n");
                }
                fflush(stdout);
                        
                continue;
            }
            
            message_occurence = calloc(sizeof (message_occurence_t), 1);
            message_occurence->frame_id = frame_id;
            message_occurence->ts_sec = header.ts_sec;
            message_occurence->ts_usec = header.ts_usec;
            
            
            if(ret_val & PARSE_NO_VLAN) {
                message_occurence->vlan = 5000;
            } else {
                message_occurence->vlan = DOT1Q_VLAN(dot1q);
            }

            // conversation
            Index = ip->saddr;
            JLI(PValue1, conversation_array, ip->saddr);
            src_array = (Pvoid_t) * PValue1;

            JLI(PValue2, src_array, ntohl(dark->id));
            id_array = (Pvoid_t) * PValue2;

            JLI(PValue3, id_array, frame_id);
            *PValue3 = (Word_t) message_occurence;

            *PValue2 = (Word_t) id_array;
            *PValue1 = (Word_t) src_array;
            
            
            
        }
    }
    
    printf("got %d pakets\n",frame_id);
    fflush(stdout);

    printf("Counting\n");
    fflush(stdout);
    Index1 = 0;
    JLF(PValue1, conversation_array, Index1);
    while (PValue1 != NULL) {
        ip_addr_to_string(Index1, string1);
        

        src_array = (Pvoid_t) * PValue1;
        Index2 = 0;
        JLF(PValue2, src_array, Index2);
        JLC(count, src_array, 0, -1);
        
        printf("source: %s %d ids (first %d)\n", string1,count,Index2);
        fflush(stdout);
        while (PValue2 != NULL) {
            id_array = (Pvoid_t) * PValue2;

            JLC(count, id_array, 0, -1);
            /**
             * Nombre de paquets attendus
             */
            if (count != 4) {
                printf("\t id: %d\n", Index2);
                
                JLI(PValue4,save_id_array,Index2);
                *PValue4=1;
                
                Index3 = 0;
                JLF(PValue3, id_array, Index3);
                while (PValue3 != NULL) {
                    message_occurence = (message_occurence_t*) * PValue3;

                    time = message_occurence->ts_sec + (((float) message_occurence->ts_usec) / 1000 / 1000);

                    timeinfo = localtime((time_t*)&(message_occurence->ts_sec));

                    strftime(string1, BUFFER_SIZE, "%Y-%m-%d %H:%M:%S", timeinfo);

                    printf("\t\tframe %d vlan %d %s.%06d\n", message_occurence->frame_id, message_occurence->vlan, string1, message_occurence->ts_usec);

                    Index4 = message_occurence->frame_id;
                    JLI(PValue4,save_frame_array,Index4);
                    *PValue4=1;
                    
                    JLN(PValue3, id_array, Index3);
                }
            }

            JLN(PValue2, src_array, Index2);
        }


        JLN(PValue1, conversation_array, Index1);
    }
    
    
    printf("Second pass\n");
    fflush(stdout);
    rewind(fpr);
    pcap_read_headers(&pcap_hdr, fpr);
    frame_id = 0;
    
    while (pcap_read_packet(&header, (void *) buffer, fpr) == 0) {
        frame_id++;
        
        Index1 = frame_id;
        JLG(PValue1, save_frame_array, Index1);
        
        ret_val = parse_packet(&header,buffer,&ether,&dot1q,&ip,&udp,&dark);

            
        if(ret_val & PARSE_SKIP) {
            fwrite(&header,sizeof(pcaprec_hdr_t),1,fpw);
            fwrite(buffer,header.incl_len,1,fpw);
            continue;
        }
        
        Index2 = ntohl(dark->id);
        JLG(PValue2, save_id_array, Index2);
        
        
        
        if(PValue1 != NULL || PValue2 != NULL) {
            fwrite(&header,sizeof(pcaprec_hdr_t),1,fpw);
            fwrite(buffer,header.incl_len,1,fpw);
        }
    }
    

    pcap_close_file(fpr);
    return (EXIT_SUCCESS);
}

