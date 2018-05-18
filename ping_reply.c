#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> 
#include <netinet/ip_icmp.h>


char *IFACE_NAME = "eth0";
unsigned char NEXT_HWADDR[ETH_ALEN] = { 0x00,0x0c,0x29,0x3f,0x3b,0x15 };
unsigned char LOCAL_HWADDR[ETH_ALEN] = { 0x00,0x0c,0x29,0x3f,0x2a,0x14 };
unsigned char BROADCAST_HWADDR[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
char *LOCAL_IP = "192.168.3.2"; 
char *DST_IP
#define buffer_max = 65536

char recv_buffer[buffer_max];


unsigned short cal_chksum(unsigned short *addr, int len)
{
	unsigned long result = 0;
	while(len > 1)
	{
		result += *addr;
		addr = addr + 1;
		len = len - 2;   // acculate each bit data
	}

	if(len % 2 == 1)
	{
		result += *(unsigned char *) addr;   // extend the last bit
	}
	result = (result >> 16) + (result & 0xffff); //high 16 bit + low 16 bit
	result += result >> 16;
	return (unsigned short)~result;
}


int main()
{
    int sock_r;
	sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	

	/* Receive ping request, send ping reply */
	while (1) {
		//Receive a network packet and copy in to buffer
		int  result = recvfrom(sock_r,buffer,BUFFSIZ,0, NULL, NULL);
        if(result == -1)
            {
                printf("wrong recv \n");
            }
		// Extracting the Ethernet header
		struct ethhdr *eth = (struct ethhdr *)(buffer);
		if (strncmp((char *)eth->h_source, (char *)LOCAL_HWADDR, ETH_ALEN) &&
			strncmp((char *)eth->h_source, (char *)BROADCAST_HWADDR, ETH_ALEN))
			continue;
		printf("Ethernet header checked\n");
		

		// Extracting the IP header
		struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
		struct in_addr local_in_addr, dst_in_addr;
		inet_aton(LOCAL_IP, &local_in_addr);
		dst_in_addr.s_addr = ip->daddr;
		if (local_in_addr.s_addr != dst_in_addr.s_addr || ip->protocol != 1)
			continue;
		printf("IP header checked\n");

		// Extracting the ICMP header
		struct icmphdr *icmp_hdr = 
			(struct icmphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
		if (icmp_hdr->type  != ICMP_ECHO)
			continue;
		printf("ICMP header checked\n");

		/* Send ping reply */
		// Change the source and destination MAC address
		memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
		memcpy(eth->h_dest, NEXT_HOP_HWADDR, ETH_ALEN);

		// Change the source and destination IP address
		ip->daddr = ip->saddr;
		ip->saddr = inet_addr(LOCAL_IP);
		ip->check = 0;
		ip->check = cal_chksum((unsigned short *)ip, sizeof(struct iphdr));
		
		// Change ICMP header
		icmp_hdr->type = ICMP_ECHOREPLY;	
		icmp_hdr->checksum = 0;
		icmp_hdr->checksum = cal_chksum((unsigned short *)icmp_hdr, 
				sizeof(struct icmphdr) + sizeof(struct timeval));

		// Getting the index of the interface to send a packet
		struct ifreq ifreq_i;
		memset(&ifreq_i,0,sizeof(ifreq_i));
		//giving name of Interface
		strncpy(ifreq_i.ifr_name, IFACE_NAME, IFNAMSIZ-1); 
		//getting Interface Index 
		ioctl(sock_r, SIOCGIFINDEX, &ifreq_i); 

		struct sockaddr_ll sadr_ll;
		memset(&sadr_ll, 0, sizeof(sadr_ll));
		sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex; // index of interface
		sadr_ll.sll_halen = ETH_ALEN; // length of destination mac address
		memcpy(sadr_ll.sll_addr, NEXT_HOP_HWADDR, ETH_ALEN);
		sadr_ll.sll_family = AF_PACKET;

		int result_send = sendto(sock_r, buffer, buflen, 0,
				(const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll));
        if(send != -1)
		    printf("Succeed in sending a ping reply\n");

	} // while(1)

}
