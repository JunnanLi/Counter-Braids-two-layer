#include "readPcap.h"

void readTrace(FILE *fp_pcap, FILE *fp_pkt){
	struct pcap_file_header *file_header;
	struct pcap_pkthdr *pkt_header;
	tIPHeader *ip_header;
	tTCPHeader *tcp_header;

	int pkt_offset = 0;
	int i =0;

	file_header = (struct pcap_file_header*)malloc(sizeof(struct pcap_file_header));
	pkt_header = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
	ip_header = (tIPHeader *)malloc(sizeof(tIPHeader));
	tcp_header = (tTCPHeader *)malloc(sizeof(tTCPHeader));

	if((fp_pcap = fopen("../space_saving/equinix-chicago.dirA.20151217-130100.UTC.anon.pcap", "r")) == NULL){
		printf("open pcap file error!\n");
		exit(0);
	}
	if((fp_pkt = fopen("result_pkt.txt", "w")) == NULL){
		printf("open result_pkt from pacp file error!\n");
		exit(0);
	}
	fread(file_header, sizeof(struct pcap_file_header), 1, fp_pcap);

	pkt_offset = 24;

	//while((fseek(fp_pcap, pkt_offset, SEEK_SET) == 0) && (i <100)){
	while(fseek(fp_pcap, pkt_offset, SEEK_SET) == 0){
		i++;

		// read pkt_header;
		if(fread(pkt_header, 16, 1, fp_pcap) != 1){
			printf("read end of pacp file\n");
			break;
		}
		pkt_offset += 16 + pkt_header->caplen;

		// ethernet
		//fseek(fp_pcap, 14, SEEK_CUR);

		// read ip_header;
		if(fread(ip_header, sizeof(tIPHeader), 1, fp_pcap) != 1){
			printf("%d: can not read ip_header\n", i);
			break;
		}

		// read tcp_header if any;
		if(ip_header->protocol != 0x06)
			continue;

		if(fread(tcp_header, sizeof(tTCPHeader), 1, fp_pcap) != 1){
			printf("%d: can not read tcp_header\n", i);
			break;
		}

		if(ip_header->protocol == 0x6)
			fprintf(fp_pkt, "%x\t%x\t%hd\t%hd\t%d\t%u\t%d\t%d\n", ntohl(ip_header->src_ip), ntohl(ip_header->dst_ip),
				ntohs(tcp_header->src_port), ntohs(tcp_header->dst_port), ip_header->protocol, ntohs(ip_header->totalLen),
				pkt_header->ts.tv_sec, pkt_header->ts.tv_usec);
	}
	fclose(fp_pcap);
	fclose(fp_pkt);
	printf("num of tcp_pkt: %d\n",i);
}

// i = 2771_4907 include tcp and udp;
