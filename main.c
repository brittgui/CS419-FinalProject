#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#define PCAP_SRC_FILE 2

int icmpCt = 0, tcpCt = 0, udpCt = 0;
char httpIP[BUFSIZ][INET_ADDRSTRLEN];
FILE *p_log;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void print_icmp(const u_char *, int, struct timeval);
void print_ip_packet(const u_char *, int);

int main(int argc, char **argv){
	pcap_t *handle;
	struct pcap_pkthdr header;
	const uint8_t *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[BUFSIZ];

	if(argc != 2){
		printf("Incorrect arguments, use: %s filename\n", argv[0]);
		return -1;
	}

	handle = pcap_open_offline(argv[1], errbuf);
	
	if (handle == NULL){
		fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf); 
		return 0; 
	} 

	p_log = fopen("log.txt", "w");
	fprintf(p_log, "ICMP PACKETS\n");

	if(p_log == NULL){
		printf("Couldn't create log.txt\n"); 
	}	
	
	if(pcap_loop(handle, 0, packetHandler, NULL) < 0){
		fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(handle));
		return 0;
	}

	printf("Packet Summary: ICMP: %d |TCP: %d |UDP: %d\n",
		       	icmpCt, tcpCt, udpCt);

	printf("See log.txt for ICMP Packet log.\n"); 

	return 0;

}



void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet){
	const struct ether_header* ethernetHeader;
	const struct ip* iph;
//	char sourceIP[INET_ADDRSTRLEN];
	char destIP[INET_ADDRSTRLEN];
//	u_int sourcePort, destPort;
//	int dataLength = 0;

	ethernetHeader = (struct ether_header*)packet;
	if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP){
		if (iph->ip_p == IPPROTO_TCP){
			tcpCt = tcpCt+1;
		} else if (iph->ip_p == IPPROTO_UDP){
			udpCt = udpCt+1; 
		} else if (iph->ip_p == IPPROTO_ICMP){
			icmpCt = icmpCt+1;
			print_icmp(packet, pkthdr->len, pkthdr->ts); 
			
		}	
	}
}

void print_ip_info(const u_char *buff, int n){

	char sourceIP[INET_ADDRSTRLEN], destIP[INET_ADDRSTRLEN];

	struct ip *iph = (struct ip*)(buff + sizeof(struct ether_header));

	fprintf(p_log, "|Source: %s ",inet_ntop(AF_INET, &(iph->ip_src), sourceIP, INET_ADDRSTRLEN));

	fprintf(p_log, "|Dest: %s ",inet_ntop(AF_INET, &(iph->ip_dst), destIP, INET_ADDRSTRLEN));

}


void print_icmp(const u_char *buff, int n, struct timeval pkt_time){

	unsigned short iph_len;

	struct ip *iph = (struct ip*)(buff + sizeof(struct ether_header));
	iph_len = iph->ip_hl * 4;

	struct icmphdr *icmph = (struct icmphdr*)(buff + iph_len + sizeof(struct ethhdr));	
	fprintf(p_log, "\nTime: %ld.%06ld ", pkt_time.tv_sec, pkt_time.tv_usec);

	print_ip_info(buff, n);

	fprintf(p_log, "|Type: %d ", (unsigned int)(icmph->type));

	if((unsigned int)(icmph->type) == ICMP_ECHO){
		fprintf(p_log, "(Echo (PING) Request)");
	}	
	fprintf(p_log, "\n");

}
