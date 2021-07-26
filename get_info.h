#ifndef GET_INFO_H
#define GET_INFO_H

#endif // GET_INFO_H

#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

void mac(uint8_t* macAddr);
char *read_data(const u_char* packet, uint8_t ip_size, uint8_t ip_hsize, uint8_t tcp_off);
