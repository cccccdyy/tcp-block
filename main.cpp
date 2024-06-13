#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "ethhdr.h"
#include "tcphdr.h"
#include "iphdr.h"

Mac my_mac;
Ip my_ip;

typedef struct _pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
}pseudo_header;

void usage () {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

void debug(char* ptr, uint32_t num) {
    for (int i = 0; i < num; i++)
        printf("%02X ", ptr[i]);
}

int GetAddrs(const char* interface, Mac* my_mac, Ip* my_ip) {   
	struct ifreq ifr;
	int sockfd, ret;
	char ipstr[30] = {0};
    uint8_t macbuf[6] = {0};

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("socket() FAILED\n");
		return -1;
	}

	strncpy(ifr.ifr_name, interface, IFNAMSIZ);

	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr); // get mac addr
	if(ret < 0){
		printf("ioctl() FAILED\n");
		close(sockfd);
		return -1;
	}
	memcpy(macbuf, ifr.ifr_hwaddr.sa_data, 6); // mac addr len = 6
    *my_mac = Mac(macbuf);

	ret = ioctl(sockfd, SIOCGIFADDR, &ifr); // get ip addr
	if(ret < 0){
		printf("ioctl() FAILED\n");
		close(sockfd);
		return -1;
	}
	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr, sizeof(struct sockaddr));
	*my_ip = Ip(ipstr);
	close(sockfd);

	return 0;
}

uint16_t Checksum(uint16_t* ptr, int len){
	uint32_t sum = 0;
	uint16_t odd = 0;

	while (len > 1){
		sum += *ptr++;
		len -= 2;
	}

	if (len == 1){
		*(uint8_t *)(&odd) = (*(uint8_t *)ptr);
		sum += odd;
	}

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t)~sum;
}

int main (int argc, char* argv[]) {
    if (argc != 3) { // check argc
        usage();
        return 0;
    }

    char* dev = (char*)malloc(strlen(argv[1]) + 1); // get interface name
    memset(dev, 0, strlen(argv[1]) + 1);
    strncpy(dev, argv[1], strlen(argv[1]));
    GetAddrs(dev, &my_mac, &my_ip); // get mac addr & ip addr 

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    // get pattern
    char* pattern = (char*)malloc(strlen(argv[2]) + 1); // get pattern
    memset(pattern, 0, strlen(argv[2]) + 1);
    strncpy(pattern, argv[2], strlen(argv[2])); // copy ->  Host: gilgil.net 

    // resources 
    struct pcap_pkthdr* header;
    const u_char* packet;
    PEthHdr ethernet_hdr;
    PIpHdr ip_hdr;
    PTcpHdr tcp_hdr;
    int res;

    while (true) {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
		else if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

        ethernet_hdr = (PEthHdr)packet; // get eth header
        if (ethernet_hdr->type() == EthHdr::Ip4) { // ipv4
            ip_hdr = (PIpHdr)((uint8_t*)ethernet_hdr + sizeof(struct EthHdr)); // get ip header 
            uint32_t iphdr_len = ip_hdr->ip_len * 4;
            uint32_t ippkt_len = ntohs(ip_hdr->total_len);
            uint32_t pkt_len = ippkt_len + sizeof(struct EthHdr);

            if (ip_hdr->proto == 6) { // tcp
                tcp_hdr = (PTcpHdr)((uint8_t*)ip_hdr + iphdr_len); // get tcp header
                uint32_t tcphdr_len = tcp_hdr->th_off * 4;
                uint32_t tcpdata_len = ippkt_len - iphdr_len - tcphdr_len;

                if (tcpdata_len == 0) continue; // no data
                
                char* tcp_data = (char*)malloc(tcpdata_len + 1);
                memset(tcp_data, 0, tcpdata_len + 1); // null terminatino for strstr() 
                strncpy(tcp_data, (char*)((uint8_t*)tcp_hdr + tcphdr_len), tcpdata_len);

                if (strstr(tcp_data, pattern) && !strncmp(tcp_data, "GET", 3)) { // pattern found

                    // backward packet (FIN) -> client
                    int rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
                    int value = 1;
                    setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, (char *)&value, sizeof(value));

                    struct sockaddr_in rawaddr; // set addr
                    rawaddr.sin_family = AF_INET;
                    rawaddr.sin_port = tcp_hdr->sport; // network byte order
                    rawaddr.sin_addr.s_addr = (uint32_t)ip_hdr->sip_; // network byte order

                    const char* tcpdata_my = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n"; // tcp data
                    uint16_t iphdr_my_len = sizeof(IpHdr), tcphdr_my_len = sizeof(TcpHdr), tcpdata_my_len = strlen(tcpdata_my);
                    uint16_t my_total_len = iphdr_my_len + tcphdr_my_len + strlen(tcpdata_my);

                    char* my_packet = (char*)malloc(my_total_len + 1); // make packet 
                    memset(my_packet, 0, my_total_len + 1);

                    PIpHdr iphdr_my = (PIpHdr)my_packet; // ip header
                    PTcpHdr tcphdr_my = (PTcpHdr)(my_packet + iphdr_my_len); // tcp header
                    memcpy(my_packet + iphdr_my_len + tcphdr_my_len, tcpdata_my, tcpdata_my_len); // copy tcp data to new packet

                    tcphdr_my->sport = tcp_hdr->dport; // from server
                    tcphdr_my->dport = tcp_hdr->sport; // to clinet 
                    tcphdr_my->seqnum = tcp_hdr->acknum; // sequence number 
                    tcphdr_my->acknum = htonl(ntohl(tcp_hdr->seqnum) + tcpdata_len); // sequence number
                    tcphdr_my->th_off = tcphdr_my_len / 4; // tcp header len = 20 / 4
                    tcphdr_my->flags = 0b00010001; // ACK | FIN flag
                    tcphdr_my->win = htons(60000); // Window Size

                    iphdr_my->ip_len = iphdr_my_len / 4; // ip header len = 20 / 4
                    iphdr_my->ip_v = 4; // ipv4
                    iphdr_my->total_len = htons(my_total_len);
                    iphdr_my->ttl = 128; // ttl (128 ~ 255)
                    iphdr_my->proto = 6; // tcp
                    iphdr_my->sip_ = ip_hdr->dip_; // from server
                    iphdr_my->dip_ = ip_hdr->sip_; // to client

                    pseudo_header* psdheader = (pseudo_header*)malloc(sizeof(pseudo_header) + 1); // pseudo header for tcp checksum
                    memset(psdheader, 0, sizeof(pseudo_header) + 1);
                    psdheader->source_address = ip_hdr->dip_;
                    psdheader->dest_address = ip_hdr->sip_;
                    psdheader->protocol = IPPROTO_TCP;
                    psdheader->tcp_length = htons(tcphdr_my_len + tcpdata_my_len);

                    uint32_t tcp_checksum = Checksum((uint16_t*)tcphdr_my, tcphdr_my_len + tcpdata_my_len) + Checksum((uint16_t*)psdheader, sizeof(pseudo_header));
                    tcphdr_my->check = (tcp_checksum & 0xffff) + (tcp_checksum >> 16);
                    iphdr_my->check = Checksum((uint16_t*)iphdr_my, iphdr_my_len);

                    if (sendto(rawsock, my_packet, my_total_len, 0, (struct sockaddr *)&rawaddr, sizeof(rawaddr)) < 0) {
                        perror("Send failed");
                        return -1;
                    }
                    free(psdheader);
                    free(my_packet);
                    close(rawsock);


                    // forward packet (RST) -> server 
                    uint32_t newpkt_len = sizeof(EthHdr) + iphdr_len + sizeof(TcpHdr); // no data, no optional header
                    char* newpkt = (char*)malloc(newpkt_len + 1);
                    memset(newpkt, 0, newpkt_len + 1);
                    memcpy(newpkt, packet, newpkt_len);

                    ethernet_hdr = (PEthHdr)newpkt;
                    ip_hdr = (PIpHdr)((char*)ethernet_hdr + sizeof(EthHdr));
                    tcp_hdr = (PTcpHdr)((char*)ip_hdr + iphdr_len);

                    ethernet_hdr->smac_ = my_mac; // modify smac as mine
                    ip_hdr->total_len = htons(iphdr_len + sizeof(TcpHdr));
                    ip_hdr->check = 0; // initialize checksum 
                    tcp_hdr->th_off = sizeof(TcpHdr) / 4; // tcp header length
                    tcp_hdr->seqnum = htonl(ntohl(tcp_hdr->seqnum) + tcpdata_len);
                    tcp_hdr->flags = 0b00010100; // RST | ACK flag
                    tcp_hdr->check = 0; // initialize checksum

                    psdheader = (pseudo_header*)malloc(sizeof(pseudo_header) + 1); // pseudo header for tcp checksum
                    memset(psdheader, 0, sizeof(pseudo_header) + 1);
                    psdheader->source_address = ip_hdr->sip_;
                    psdheader->dest_address = ip_hdr->dip_;
                    psdheader->protocol = IPPROTO_TCP;
                    psdheader->tcp_length = htons(sizeof(TcpHdr));

                    tcp_checksum = Checksum((uint16_t*)tcp_hdr, sizeof(TcpHdr)) + Checksum((uint16_t*)psdheader, sizeof(pseudo_header));
                    tcp_hdr->check = (tcp_checksum & 0xffff) + (tcp_checksum >> 16);
                    ip_hdr->check = Checksum((uint16_t*)ip_hdr, iphdr_len);
 
                    if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(newpkt), newpkt_len)) {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                    }

                    free(psdheader);
                    free(newpkt);
                }
            }
        }
    }
}