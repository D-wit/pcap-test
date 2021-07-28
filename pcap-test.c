#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <features.h>
#include <libnet.h>
#include "get_info.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        struct libnet_ethernet_hdr* ethHeader = (struct libnet_ethernet_hdr*)packet;
        struct libnet_ipv4_hdr* ipv4Header = (struct libnet_ipv4_hdr*)(sizeof(struct libnet_ethernet_hdr) + packet);
        struct libnet_tcp_hdr* tcpHeader = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + (ipv4Header->ip_len));

        if(ipv4Header->ip_p == 6){
            printf("\n%u bytes captured\n", header->caplen);
            printf("Src MAC: "); mac(ethHeader->ether_shost); printf("\nDst MAC: "); mac(ethHeader->ether_dhost);
            printf("\nSrc IP: %s",inet_ntoa(ipv4Header->ip_src)); printf("\nSrc IP: %s",inet_ntoa(ipv4Header->ip_dst));
            printf("\nSrc Port: %d\nDST Port: %d\n",ntohs(tcpHeader->th_sport),ntohs(tcpHeader->th_dport));
            read_data(packet, ipv4Header->ip_len, ipv4Header->ip_hl << 2 , tcpHeader->th_off << 2);

        }

	}

	pcap_close(pcap);
}
