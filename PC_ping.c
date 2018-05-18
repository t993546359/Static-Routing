#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<signal.h>

#include<sys/socket.h>
#include<linux/if_packet.h>
#include<net/ethernet.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netinet/ip_icmp.h>
#include<linux/if_ether.h>
#include<netinet/ip.h>
#include<netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <sys/time.h>
#include <assert.h>


const char *IFACE_NAME = "eth0";
char *LOCAL_IP = "192.168.1.2";
char *DST_IP = "192.168.3.2";
#define BUFFER_MAX 1024
#define ICMP_HDR_LEN sizeof(struct icmphdr)
#define ICMP_PACKET_LEN (ICMP_HDR_LEN+sizeof(struct timeval))


char send_buffer[BUFFER_MAX];
char recv_buffer[BUFFER_MAX];
unsigned char PC_HWADDR[ETH_ALEN] = {0x00,0x0c,0x29,0x0a,0xe1,0xf9}; // U571
unsigned char NEXT_HWADDR[ETH_ALEN] = {0x00,0x0c,0x29,0x66,0xe0,0x07};     // U572    


struct sockaddr_ll sadr_ll;
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

	sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    int uid = getpid();

    struct ifreq ifreq_i;
	memset(&ifreq_i,0,sizeof(ifreq_i));
	//giving name of Interface
	strncpy(ifreq_i.ifr_name, IFACE_NAME, IFNAMSIZ-1); 
	//getting Interface Index 
	ioctl(sockfd, SIOCGIFINDEX, &ifreq_i); 
	sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex; // index of interface

	sadr_ll.sll_halen = ETH_ALEN;
	sadr_ll.sll_family = AF_PACKET;
	memcpy(sadr_ll.sll_addr, NEXT_HWADDR, ETH_ALEN);

    int sequence = 1;

    // send a packet
    memset(send_buffer,0,BUFFER_MAX);

    //设置数据报头
    struct ethhdr *eth_head = (struct ethhdr *)(send_buffer);
    memcpy(eth_head->h_source,PC_HWADDR,ETH_ALEN);
    memcpy(eth_head->h_dest,NEXT_HWADDR,ETH_ALEN);
    eth_head->h_proto = htons(ETH_P_IP);


    //设置ip报头
    struct iphdr *ip_head = (struct iphdr *)(send_buffer + sizeof(struct ethhdr));
    ip_head->version = 4;
	ip_head->ihl = 5;
	ip_head->ttl = 64;
	ip_head->protocol = 1;	// ICMP
	ip_head->saddr = inet_addr(LOCAL_IP);
	ip_head->daddr = inet_addr(DST_IP);
    ip_head->tot_len = htons(sizeof(struct iphdr) + ICMP_PACKET_LEN);
	ip_head->check = cal_chksum((void *)ip_head, sizeof(struct iphdr));
	
    
    //icmp报头
   	struct icmp* icmp_head = (struct icmphdr *)(send_buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));

	icmp_head->icmp_type  = ICMP_ECHO;
	icmp_head->icmp_code  = 0;
    	icmp_head->icmp_id = uid;
	icmp_head->icmp_seq = sequence;

    	gettimeofday((struct timeval *)((char *)icmp_head+sizeof(struct icmphdr)),NULL);
	icmp_head->icmp_cksum =cal_chksum((unsigned short*)icmp_head, ICMP_PACKET_LEN);

	/* Send Ethernet frame */
	int total_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + ICMP_PACKET_LEN;
	int send_end = sendto(sockfd, send_buffer, total_len, 0,
			(const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll));
    if(send_end == -1)
    {
        printf("error, in pc we failed to send");
    }


    // --------------------------------------------


    // reply part
    while(1)
   {
        struct ethhdr *re_eth_head = (struct ethhdr *)(recv_buffer);
        struct iphdr *re_ip_head = (struct iphdr *)(recv_buffer + sizeof(struct ethhdr));
        struct icmphdr *re_icmp_head = (struct icmphdr *)(recv_buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
        struct timeval *send_tv  = (struct timeval *)(icmp_head + 1);
        
        if(strncmp(re_eth_head->h_dest,PC_HWADDR,ETH_ALEN) != 0 
        || re_eth_head->h_proto != htons(ETH_P_IP))
        {
            continue;
        }
        if(icmp_head->icmp_type != ICMP_ECHOREPLY || icmp_head->icmp_id != uid )
            continue;
        struct in_addr temp;
        inet_aton(LOCAL_IP,&temp);
        if(re_ip_head->daddr != temp.s_addr)
            continue;
        
        struct timeval now_tv;
	    gettimeofday(&now_tv,NULL);

        
        printf("%d bytes from %s:\ticmp_seq=%d\tttl=%d\ttime=%.1fms\n",
		ICMP_PACKET_LEN,	
		DST_IP,
		ntohs(re_icmp_head->un.echo.sequence ),
		re_ip_head->ttl,
		1000*(now_tv.tv_sec-send_tv->tv_sec)+(now_tv.tv_usec-send_tv->tv_usec)/1000.0
		);

   }
}
