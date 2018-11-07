#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

struct ethernet{
	uint8_t destination_address[ETHER_ADDR_LEN];
	uint8_t source_address[ETHER_ADDR_LEN];
	uint16_t ethernet_type;
};


const char method[6][10]={"GET","POST","HEAD","PUT","DELETE","OPTIONS"};
const char warning[8]="blocked";

uint8_t my_mac_address[ETHER_ADDR_LEN];


void get_mac_address(char * interface, uint8_t * addr){
	struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024];
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	ioctl(sock, SIOCGIFCONF, &ifc);
	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));
	for (; it != end; ++it) {
		strcpy(ifr.ifr_name, it->ifr_name);
		if(!strcmp(interface,ifr.ifr_name)){
			if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
				if (! (ifr.ifr_flags & IFF_LOOPBACK)) { 
					if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
						memcpy(addr, ifr.ifr_hwaddr.sa_data, 6);   
						break;
                		}
            		}
        	}
    	}
    }
}


void make_rst_packet(u_char * p, uint32_t seq, uint32_t ack, uint32_t ip_hlen, uint32_t tcp_hlen, uint32_t option=0){
	
	/*
	struct ethernet * eth_ptr=(struct ethernet *)p;
	if(option)for(int i=0;i<ETHER_ADDR_LEN;i++)eth_ptr->destination_address[i]=eth_ptr->source_address[i];
	for(int i=0;i<ETHER_ADDR_LEN;i++)eth_ptr->source_address[i]=my_mac_address[i];
	*/

	if(option){
		struct ethernet * eth_ptr=(struct ethernet *)p;
		uint8_t tmp_address[ETHER_ADDR_LEN];
		for(int i=0;i<ETHER_ADDR_LEN;i++)tmp_address[i]=eth_ptr->destination_address[i];
		for(int i=0;i<ETHER_ADDR_LEN;i++)eth_ptr->destination_address[i]=eth_ptr->source_address[i];
		for(int i=0;i<ETHER_ADDR_LEN;i++)eth_ptr->source_address[i]=tmp_address[i];
	}

	if(option){
		struct ip * ip_ptr=(struct ip *)(p+sizeof(struct ethernet));
		uint32_t tmp_ip=ip_ptr->ip_dst.s_addr;
		ip_ptr->ip_dst.s_addr=ip_ptr->ip_src.s_addr;
		ip_ptr->ip_src.s_addr=tmp_ip;
	}

	struct tcphdr * tcp_ptr=(struct tcphdr *)(p+sizeof(struct ethernet)+ip_hlen);

	if(option){
		struct tcphdr * tcp_ptr=(struct tcphdr *)(p+sizeof(struct ethernet)+ip_hlen);
		uint16_t tmp_port=tcp_ptr->th_dport;
		tcp_ptr->th_dport=tcp_ptr->th_sport;
		tcp_ptr->th_sport=tmp_port;
	}

	tcp_ptr->th_seq=seq;
	tcp_ptr->th_ack=ack;
	tcp_ptr->th_flags&=0;
	tcp_ptr->th_flags|=TH_RST;
	tcp_ptr->th_flags|=TH_ACK;
	tcp_ptr->th_win=0;
	tcp_ptr->th_sum=0;
	tcp_ptr->th_urp=0;
	
}
void make_fin_packet(u_char * p, uint32_t seq, uint32_t ack, uint32_t ip_hlen, uint32_t tcp_hlen, uint32_t data_len){
	
	/*
	struct ethernet * eth_ptr=(struct ethernet *)p;
	for(int i=0;i<ETHER_ADDR_LEN;i++)eth_ptr->destination_address[i]=eth_ptr->source_address[i];
	for(int i=0;i<ETHER_ADDR_LEN;i++)eth_ptr->source_address[i]=my_mac_address[i];
	*/
	struct ethernet * eth_ptr=(struct ethernet *)p;
	uint8_t tmp_address[ETHER_ADDR_LEN];
	for(int i=0;i<ETHER_ADDR_LEN;i++)tmp_address[i]=eth_ptr->destination_address[i];
	for(int i=0;i<ETHER_ADDR_LEN;i++)eth_ptr->destination_address[i]=eth_ptr->source_address[i];
	for(int i=0;i<ETHER_ADDR_LEN;i++)eth_ptr->source_address[i]=tmp_address[i];
	
	struct ip * ip_ptr=(struct ip *)(p+sizeof(struct ethernet));
	uint32_t tmp_ip=ip_ptr->ip_dst.s_addr;
	ip_ptr->ip_dst.s_addr=ip_ptr->ip_src.s_addr;
	ip_ptr->ip_src.s_addr=tmp_ip;
	
	struct tcphdr * tcp_ptr=(struct tcphdr *)(p+sizeof(struct ethernet)+ip_hlen);
	uint16_t tmp_port=tcp_ptr->th_dport;
	tcp_ptr->th_dport=tcp_ptr->th_sport;
	tcp_ptr->th_sport=tmp_port;

	tcp_ptr->th_seq=ack;
	tcp_ptr->th_ack=htonl(ntohl(seq)+data_len);
	tcp_ptr->th_flags&=0;
	tcp_ptr->th_flags|=TH_FIN;
	tcp_ptr->th_flags|=TH_ACK;
	tcp_ptr->th_win=0;
	tcp_ptr->th_sum=0;
	tcp_ptr->th_urp=0;
	memcpy(p+sizeof(struct ethernet)+ip_hlen+tcp_hlen, warning, strlen(warning));
	
}

void check(char * p, int len, u_char * fd_rstp, u_char * bk_rstp, u_char * finp, pcap_t* fp){

	int i;
	struct ethernet * a_ptr=(struct ethernet *)p;
	
	if(ntohs(a_ptr->ethernet_type)==ETHERTYPE_IP){
		struct ip * ip_ptr=(struct ip *)(p+sizeof(struct ethernet));
		if((ip_ptr->ip_v==4)&&(ip_ptr->ip_p==IPPROTO_TCP)){
			
			unsigned int ip_hlen=(ip_ptr->ip_hl)*4;
			unsigned int ip_tlen=ip_ptr->ip_len;
			struct tcphdr * tcp_ptr=(struct tcphdr *)(p+sizeof(struct ethernet)+ip_hlen);
			unsigned int tcp_hlen=(tcp_ptr->th_off)*4;
			unsigned int data_len=(ntohs(ip_tlen)-(ip_hlen+tcp_hlen));
			const char * data=(const char *)(p+sizeof(struct ethernet)+ip_hlen+tcp_hlen);
			
			uint32_t seq=tcp_ptr->th_seq;
			uint32_t ack=tcp_ptr->th_ack;
			
			
			for(i=0;i<6;i++){
				if(!strncmp(data, method[i],strlen(method[i])))break;
			}
			if(i==6){
				memcpy(fd_rstp,p,sizeof(struct ethernet)+ip_hlen+tcp_hlen);
				memcpy(bk_rstp,p,sizeof(struct ethernet)+ip_hlen+tcp_hlen);
				
											
				make_rst_packet(fd_rstp, htonl(ntohl(seq)+data_len), ack, ip_hlen, tcp_hlen);
				make_rst_packet(bk_rstp, ack, htonl(ntohl(seq)+data_len), ip_hlen, tcp_hlen,1);
											
				pcap_inject(fp, fd_rstp, sizeof(struct ethernet)+ip_hlen+tcp_hlen);
				pcap_inject(fp, bk_rstp, sizeof(struct ethernet)+ip_hlen+tcp_hlen);

				memset(fd_rstp, '\x0',sizeof(struct ethernet)+ip_hlen+tcp_hlen);
				memset(bk_rstp, '\x0',sizeof(struct ethernet)+ip_hlen+tcp_hlen);
			}
			else{
				memcpy(fd_rstp,p,sizeof(struct ethernet)+ip_hlen+tcp_hlen);
				memcpy(finp,p,sizeof(struct ethernet)+ip_hlen+tcp_hlen);
				
				make_rst_packet(fd_rstp, htonl(ntohl(seq)+data_len), ack, ip_hlen, tcp_hlen);
				make_fin_packet(finp, seq, ack, ip_hlen, tcp_hlen, data_len);

				pcap_inject(fp, fd_rstp, sizeof(struct ethernet)+ip_hlen+tcp_hlen);
				pcap_inject(fp, finp, sizeof(struct ethernet)+ip_hlen+tcp_hlen+strlen(warning));

				memset(fd_rstp, '\x0',sizeof(struct ethernet)+ip_hlen+tcp_hlen);
				memset(finp, '\x0',sizeof(struct ethernet)+ip_hlen+tcp_hlen+strlen(warning));
			}							
		}
	}
}			


void usage() {
  printf("syntax: tcp_block <interface>\n");
  printf("sample: tcp_block wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  
  get_mac_address(dev, my_mac_address);
  
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
  
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  u_char * fd_rst_packet=(u_char*)malloc(sizeof(u_char)*(sizeof(struct ethernet)+sizeof(struct ip)+sizeof(struct tcphdr)));
  u_char * bk_rst_packet=(u_char*)malloc(sizeof(u_char)*(sizeof(struct ethernet)+sizeof(struct ip)+sizeof(struct tcphdr)));
  u_char * fin_packet=(u_char*)malloc(sizeof(u_char)*(sizeof(struct ethernet)+sizeof(struct ip)+sizeof(struct tcphdr)+strlen(warning)));

  while (1) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
   
	check((char *)packet, header->caplen, fd_rst_packet, bk_rst_packet, fin_packet, handle);
  }
  
  free(fd_rst_packet);
  free(bk_rst_packet);
  free(fin_packet);
  pcap_close(handle);
  return 0;
}
