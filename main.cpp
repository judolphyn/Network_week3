#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "headers.h"

#define SIZE_ETHERNET 14

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

void print_mac(const struct sniff_ethernet *ethernet_h) {
	printf("< MAC ADDRESS >");
	printf("\nsource mac : ");
	for(int i=0;i<6;i++)
		printf("%02X ",ethernet_h->ether_shost[i]);
	printf("\ndestination mac : ");
	for(int i=0;i<6;i++)
		printf("%02X ",ethernet_h->ether_dhost[i]);
	printf("\n\n");	
}

void print_ip(const struct sniff_ip *ip_h) {
	printf("< IP ADDRESS >\n");
	printf("source ip : %s\n",inet_ntoa(ip_h->ip_src));
	printf("destination ip : %s\n\n",inet_ntoa(ip_h->ip_dst));
}

void print_port(const struct sniff_tcp *tcp_h) {
	printf("< TCP Port Number >\n");
	printf("source port : %hu\n",ntohs(tcp_h->th_sport));
	printf("destination port : %hu\n\n",ntohs(tcp_h->th_dport));
}

void print_hex(const u_char *payload, u_int len) {
	printf("< Payload hex value >\n");
	printf("Payload len : %u\n",len);
	if(len>16){
		printf("print only 16 values\n");
		for(int i=0;i<16;i++)
			printf("%02X ",payload[i]);
	}
	else{
		printf("print all values\n");
		for(int i=0;i<len;i++)
			printf("%02X ",payload[i]);
	}
	printf("\n\n");
}

void pcap_capture(const u_char* packet,u_int len) {
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const u_char *payload; /* Packet payload */
	
	u_int size_ip;
	u_int size_tcp;

	/* ethernet parse */
	ethernet = (struct sniff_ethernet*)(packet);
	if (ethernet->ether_type != 0x0008){
		printf("   * Not IPv4 Type\n");
		return;
	}

	/* ip header parse */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	if (ip->ip_p != 6){
		printf("   * Not TCP Type\n");
		return;
	}

	/* tcp header parse */
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	
	/* payload parse */
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	u_int payload_len = len - (SIZE_ETHERNET + size_ip + size_tcp);

	printf("\n\n\n\n   * Valid IPv4-TCP Packet!! Packet Capture Begin!!\n\n");
	print_mac(ethernet);
	print_ip(ip);
	print_port(tcp);
	print_hex(payload,payload_len);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        pcap_capture(packet,header->caplen);
    }

    pcap_close(handle);
}
