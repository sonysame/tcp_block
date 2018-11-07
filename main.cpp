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


void dump(u_char * p, int len){
	for(int i=0;i<len;i++){
		printf("%02x ",*p);
		p++;
		if((i&0x0f)==0x0f)
			printf("\n");
	}
	printf("\n===================================\n");
}

void print_mac(char * str,uint8_t * addr){
	int i;
	printf("%s: ",str);
	for(i=0;i<ETHER_ADDR_LEN-1;i++)printf("%02x:",(u_char)*(addr+i));
	printf("%02x\n",(u_char)*(addr+i));
}
void print_ip(char * str, uint32_t ip){
	int i;
	printf("%s: ",str);
	for(i=sizeof(ip)-1;i>0;i--)printf("%d.",(ip>>(i*8))&0xff);
	printf("%d\n",ip&0xff);
}
void print_port(char * str, uint16_t port){
	printf("%s: %d\n",str,port);
}
void print_data(char * data_addr, unsigned int len=32){
	int i;
	if(len)printf("\nData:\n");
	for(i=0;i<len;i++){
		printf("%02x ",(u_char)*(data_addr+i));
		if((i&0xf)==0xf)printf("\n");
	}
}
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


const char method[6][10]={"GET","POST","HEAD","PUT","DELETE","OPTIONS"};
const char host_identifier[10]="Host: ";
const char warning[15]="warning2.or.kr";

uint8_t my_mac_address[ETHER_ADDR_LEN];
char *host_name;
const char *host;
void make_rsp_packet(u_char * p, uint32_t seq, uint32_t ack, uint32_t ip_hlen, uint32_t tcp_hlen, uint32_t data_len){
	struct ethernet * eth_ptr=(struct ethernet *)p;
	for(int i=0;i<ETHER_ADDR_LEN;i++)eth_ptr->source_address[i]=my_mac_address[i];
	struct tcphdr * tcp_ptr=(struct tcphdr *)(p+sizeof(struct ethernet)+ip_hlen);
	tcp_ptr->th_seq=htonl(ntohl(seq)+data_len);
	tcp_ptr->th_ack=ack;
	tcp_ptr->th_flags&=0;
	tcp_ptr->th_flags|=TH_RST;
	tcp_ptr->th_flags|=TH_ACK;
	tcp_ptr->th_win=0;
	tcp_ptr->th_sum=0;
	tcp_ptr->th_urp=0;
	//dump((u_char *)p,sizeof(struct ethernet)+ip_hlen+tcp_hlen);
	
}
void make_fin_packet(u_char * p, uint32_t seq, uint32_t ack, uint32_t ip_hlen, uint32_t tcp_hlen, uint32_t data_len){
	
	//printf("\n++++++++++++++++++\n");

	struct ethernet * eth_ptr=(struct ethernet *)p;
	for(int i=0;i<ETHER_ADDR_LEN;i++)eth_ptr->destination_address[i]=eth_ptr->source_address[i];
	for(int i=0;i<ETHER_ADDR_LEN;i++)eth_ptr->source_address[i]=my_mac_address[i];

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
	//dump((u_char *)p,sizeof(struct ethernet)+ip_hlen+tcp_hlen+strlen(warning));
	
}
uint32_t dump2(char * p, int len, u_char * rstp, u_char * finp, pcap_t* fp){
	int i,j;
	struct ethernet * a_ptr=(struct ethernet *)p;
	//uint8_t * dst_addr=a_ptr->destination_address;
	//uint8_t * src_addr=a_ptr->source_address;
	//print_mac("dst mac",a_ptr->destination_address);
	//print_mac("src mac",a_ptr->source_address);
	if(ntohs(a_ptr->ethernet_type)==ETHERTYPE_IP){
		struct ip * ip_ptr=(struct ip *)(p+sizeof(struct ethernet));
		if((ip_ptr->ip_v==4)&&(ip_ptr->ip_p==IPPROTO_TCP)){
			uint32_t dst_ip=ip_ptr->ip_dst.s_addr;
			uint32_t src_ip=ip_ptr->ip_src.s_addr; 
			//print_ip("dst ip",ntohl(ip_ptr->ip_dst.s_addr));
			//print_ip("src ip",ntohl(ip_ptr->ip_src.s_addr));
			unsigned int ip_hlen=(ip_ptr->ip_hl)*4;
			unsigned int ip_tlen=ip_ptr->ip_len;
			struct tcphdr * tcp_ptr=(struct tcphdr *)(p+sizeof(struct ethernet)+ip_hlen);
			unsigned int tcp_hlen=(tcp_ptr->th_off)*4;
			unsigned int data_len=(ntohs(ip_tlen)-(ip_hlen+tcp_hlen));
			//printf("%d\n",data_len);
			if(data_len>21){
				const char * data=(const char *)(p+sizeof(struct ethernet)+ip_hlen+tcp_hlen);

				for(i=0;i<6;i++){
					if(!strncmp(data, method[i],strlen(method[i])))break;
				}
				if(i!=6){
					for(i=0;i<data_len-strlen(host)-strlen(host_identifier);i++){
						if(!strncmp(data+i,host_identifier,strlen(host_identifier))){
							for(j=i+strlen(host_identifier);j<=i+strlen(host_identifier)+strlen(host)+30;j++){
								if(*(data+j)=='\xd'){
									strncpy(host_name, data+i+strlen(host_identifier),j-(i+strlen(host_identifier)));
									printf("Host name is: %s\n",host_name);	
									if(!(strcmp(host_name, host))){
										memset(host_name, '\x0',strlen(host_name));
										printf("FIND!\n");
										dump((u_char *)p, len);
										memcpy(rstp,p,sizeof(struct ethernet)+ip_hlen+tcp_hlen);
										memcpy(finp,p,sizeof(struct ethernet)+ip_hlen+tcp_hlen);

										
										//printf("\n=========================================================\n");

										uint32_t seq=tcp_ptr->th_seq;
										uint32_t ack=tcp_ptr->th_ack;
										
										make_rsp_packet(rstp, seq, ack, ip_hlen, tcp_hlen, data_len);
										make_fin_packet(finp, seq, ack, ip_hlen, tcp_hlen, data_len);
										
										pcap_sendpacket(fp, rstp, sizeof(struct ethernet)+ip_hlen+tcp_hlen);
										pcap_sendpacket(fp, finp, sizeof(struct ethernet)+ip_hlen+tcp_hlen+strlen(warning));
										
									}
									memset(host_name, '\x0',strlen(host_name));
									return -1;
								}
							}
						}
					}
				}
			}
		}
	}
	//printf("\n=========================================================\n");
}


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 3) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  host=argv[2];
  host_name=(char *)malloc(sizeof(char)*strlen(host)+30);
  get_mac_address(dev, my_mac_address);
  
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
  //pcap_t* handle=pcap_open_offline("./example2.pcapng",errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  u_char * rst_packet=(u_char*)malloc(sizeof(u_char)*(sizeof(struct ethernet)+sizeof(struct ip)+sizeof(struct tcphdr)));
  u_char * fin_packet=(u_char*)malloc(sizeof(u_char)*(sizeof(struct ethernet)+sizeof(struct ip)+sizeof(struct tcphdr)+strlen(warning)));

  int i=0;
  while (1) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("\n%u bytes captured\n", header->caplen);
	//dump((u_char *)packet, header->caplen);
	//printf("\n\n");
	
	uint32_t len=dump2((char *)packet, header->caplen, rst_packet, fin_packet, handle);
	//if(len>0) printf("SEND %d\n",pcap_sendpacket(handle, rst_packet, len));
	
	//printf("\n");
	//break;
  }
  free(host_name);
  free(rst_packet);
  free(fin_packet);
  pcap_close(handle);
  return 0;
}