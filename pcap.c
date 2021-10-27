#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

int main(int argc, char **argv){

	char *device;
	char error_buff[PCAP_ERRBUF_SIZE];
	pcap_if_t *devices, *tmp;
       	pcap_t *handle;
	const u_char *packet;
	struct pcap_pkthdr packet_header;

	//device = pcap_lookupdev(error_buff);
	if(pcap_findalldevs(&devices,error_buff) == -1){
		printf("No devices found: %s\n", error_buff);
		return 1;
	} 
	printf("list of network devices\n"); 
	int i = 0;
	tmp = devices; 
	for(tmp = devices; tmp != NULL; tmp = tmp->next){
		printf("%d :%s - %s\n", i++, tmp->name, tmp->description);
	}

	printf("Device: %s\n", devices->name);
	device = devices->name;
	
	
	
	handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buff);
	if(handle == NULL){
		printf("Error, can't open device %s\n", error_buff);
		return 1; 
	}
	packet = pcap_next(handle, &packet_header);
	if(packet == NULL){
		printf("No packet found.\n");
		return 2;
	} 


	printf("Packet capture len: %d\n", packet_header.caplen);
	printf("Packet total len: %d\n", packet_header.len);

	return 0;
} 

