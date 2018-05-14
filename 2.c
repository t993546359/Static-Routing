#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<linux/if_packet.h>
#include<net/etherent.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netinet/ip_icmp.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <sys/time.h>
#include <assert.h>

char *LOCAL_IP = "192.168.2.2";
char *DST_IP = "192.168.3.2";
#define BUFFER_MAX 1024
char send_buffer[BUFFER_MAX];
char recv_buffer[BUFFER_MAX];
char PC_HWADDR[ETH_ALEN] = {0x00,0x0c,0x29,0x0a,0xe1,0xf9}; // U571
char NEXT_HWADDR[ETH_ALEN] = {0x00,0x0c,0x29,0x66,0xe0,0x07}     // U572    


struct sockaddr_ll dest_addrl;
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


    int sockfd;

	sockfd = Socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    // send a packet
    memset(send_buffer,0,BUFFER_MAX);

    //设置数据报头
    struct ethhdr *eth_head = (struct ethhdr *)(send_buffer);
    memcpy(eth_head->h_source,PC_HWADDR,ETH_ALEN);
    memcpy(eth_head->h_dest,NEXT_HWADDR,ETH_ALEN);
    eth_head->h_proto = htons(ETH_P_IP);


    //设置ip报头
    struct iphdr *ip_head = (struct iphdr *)(send_buffer + sizeof(ethhdr));
    ip_head->version = 4;
	ip_head->ihl = 5;
	ip_head->ttl = 64;
	ip_head->protocol = 1;	// ICMP
	ip_head->saddr = inet_addr(LOCAL_IP);
	ip_head->daddr = inet_addr(DST_IP);
    ip_head->tot_len = htons(sizeof(struct iphdr) + ICMP_PACKET_LEN);
	ip_head->check = cal_chksum((void *)iph, sizeof(struct iphdr));
	
    
    //icmp报头
    struct icmphdr *icmp_head = (struct icmphdr *)(send_buffer + sizeof(ethhdr) + sizeof(iphdr));

    icmp_head->type  = ICMP_ECHO; //8 – Echo Request
	icmp_head->code  = 0;
	// icmp_hdr->checksum = 0;
	icmp_head->un.echo.id = htons(getpid());
	icmp_head->un.echo.sequence = htons(sequence);

    gettimeofday((struct timeval *)((char *)icmp_head+sizeof(struct icmphdr)),NULL);
	icmp_head->checksum =cal_chksum((unsigned short*)icmp_head, ICMP_PACKET_LEN);

	/* Send Ethernet frame */
	int total_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + ICMP_PACKET_LEN;
	int send_end = sendto(sockfd, sendbuf, total_len, 0,
			(const struct sockaddr*)&dest_addrl,sizeof(struct sockaddr_ll));
    if(send_end == -1)
    {
        printf("error, in pc we failed to send");
    }


    // --------------------------------------------


    // reply part
    while(1)
   {
       struct ethhdr *re_eth_head = (struct ethhdr *)(recv_buffer);
        struct iphdr *ip_head = (struct iphdr *)(send_buffer + sizeof(ethhdr));
        if(strncmp(re_eth_head->h_dest,LOCAL_IP,ETH_ALEN) != 0 
        || re_eth_head->h_proto != htons(ETH_P_IP))
        {
            continue;
        }
        
        
  

   }
}