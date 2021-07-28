#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <libnet.h>
#include <netinet/in.h>
#include "get_info.h"

void mac(uint8_t* macAddr)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",macAddr[0],macAddr[1],macAddr[2],macAddr[3],macAddr[4],macAddr[5]);
}

void read_data(const u_char* packet, uint8_t ip_size, uint8_t ip_hsize, uint8_t tcp_off)
{
    uint8_t* payload = (uint8_t*)(packet + sizeof(struct libnet_ethernet_hdr) + ip_hsize + tcp_off);
    uint8_t length = ntohs(ip_size) - (ip_hsize + tcp_off);

    char res[49] = {' ', };
    int sampleLength = 8 < length ? 8 : length;
    for (int i = 0 ; i < sampleLength ; i++) {
        if (i != 7)
            sprintf(&res[i*3], "%02x ", payload[i]);
        else
            sprintf(&res[i*3], "%02x\n", payload[i]);
    }


    printf("%s\n",res);
}
