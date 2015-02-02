
#include "pcap.h"
#include "utils.h"

#include <stdlib.h>

int pcap_open_read_file(FILE **fp,char *filename) {
    *fp = fopen( filename, "rb" );
    if(!(*fp)) {
        printf("Can't open file\n");
        return 1;
    }
}

int pcap_open_write_file(FILE **fp,char *filename) {
    *fp = fopen( filename, "wb" );
    if(!(*fp)) {
        printf("Can't open file\n");
        return 1;
    }
    
    pcap_hdr_t *header = malloc(sizeof(pcap_hdr_t));
    header->magic_number = 0xa1b2c3d4;
    header->network = 1;
    header->sigfigs = 64;
    header->snaplen = 10000;
    header->thiszone = 0;
    header->version_major = 2;
    header->version_minor = 4;
    
    fwrite(header,sizeof(pcap_hdr_t),1,*fp);
}

int pcap_close_file(FILE *fp) {
    return fclose(fp);
}

int pcap_read_headers(pcap_hdr_t* header,FILE *fp) {
    int header_size = sizeof(pcap_hdr_t);
    int read;
    
    
    read = fread((void *)header,1,header_size,fp);
    
    if(read != header_size) {
        printf("Can't read full pcap header: %d read over %d\n",read,header_size);
        return 1;
    }
    
    return 0;
}

int pcap_read_packet(pcaprec_hdr_t *header,void *buffer,FILE *fp){
    int header_size = sizeof(pcaprec_hdr_t);
    int payload_size,read;
    
    
    read = fread((void *)header,1,header_size,fp);
    if(read != header_size) {
        if(feof(fp)) {
            //printf("End of file\n");
            return 4;
        }
        printf("Can't read full pcap packet header: %d read over %d\n",read,header_size);
        return 1;
    }
    
    payload_size = header->incl_len;
    if(payload_size > BUFFER_SIZE) {
        printf("payload size (%d) is larger than buffer size (%d) \n",payload_size,BUFFER_SIZE);
        return 2;
    }
    
    read = fread((void *)buffer,1,payload_size,fp);
    if(read != payload_size) {
        printf("Can't read full pcap packet: %d read over %d\n",read,payload_size);
        if(ferror(fp)) printf("error");
        if(feof(fp)) printf("feof");
        return 3;
    }
    
    return 0;
}