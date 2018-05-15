#include"1.h"

using namespace std;

//struct ifreq inconf[eth_len];
void init_route_conf();

struct route_t route_tbl[eth_len];
struct device_t device_tbl[mac_tbl_len];
struct arp_t arp_tbl[arp_tbl_len]
char buffer[65535];
int main()
{
    init_route_conf();

    int sockfd = socket(AF_INET,SOCK_RAW,htons(ETH_P_ALL));

    if(sockfd < 0)
        exit(-1);
    else {
        struct sockaddr_ll addr;
        socklen_t addr_len = sizeof(addr);
        int rev_result = recvfrom(sockfd,buffer,BUF_LEN,0,(struct sockaddr *) &addr, addr_len);
        if(rev_result == -1)
            printf("wrong recv \n");
        struct ethhdr *eth_head = (struct ethhdr *)buffer;

        //  分析以太网帧头部 遍历device_table
        bool device_flag = true;
        for(int i = 0; i < mac_tbl_len;i++)
        {
            if(strncmp(device_tbl[i].hwaddr,eth_head->h_dest) == 0)
                continue;
            else device_flag = false;
        }
        if(device_flag)
            printf("The mac address has existed in the mactable! \n");
        else printf("we need to add the mac address to the table! \n");


        //分析ip数据报头。遍历route_table
        struct iphdr *ip_head = (struct iphdr *)(buffer + sizeof(ethhdr));
        //struct in_addr _ip_addr;
        //_ip
        int index;
        bool route_flag = false;
        for( index = 0; index < eth_len ; index++)
        {
            if((ip_head->daddr & route_tbl[i].mask.saddr != route_tbl[i].dest_addr)
                continue;
            else {
                printf("We have found it in route talble, intdex : %d \n",&index);
                route_flag = true;
                break;
            }
        }
        if(!route_flag)
            {
                printf("We cannot find it in route table. \n");
                exit(1);
            }
        

        // 获得下一跳的IP地址 ,遍历arp_table
        struct in_addr next_addr;
        next_addr.s_addr = ip_head->daddr;
        
        //
        //next_addr = 
        int arp_i;
        for(int arp_i = 0; arp_i < arp_tbl_len;arp_i++)
        {
            if(arp_tbl[i].ip_addr.s_addr == next_addr->s_addr)
                break;
                
        }
      //  struct in_addr temp_addr
     //   next_addr = route_tbl[index].gateway;
        //修改报头，准备重新发送数据
        memcpy(eth_head->h_source, eth_head->h_dest,ETH_ALEN);
        memcpy(eth_head->h_dest,arp_tbl[arp_i].hwaddr,ETH_ALEN);

        //获取interface
        int sockf_inter = socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IP));
        struct ifreq req;
        memset(&req,0,sizeof(req));
        strcncpy(req.ifr_name,route_tbl[index].interface,IFNAMSIZ - 1);
        ioctl(sockf_inter,SIOCGIFINDEX,&req);
        int if_index = req.ifr_ifindex;

        //重新发送数据
        int sock2send = socket(AF_PACKET, SOCK_DGRAM,htons(ETH_P_IP));
        struct sockaddr_ll dest2addr = {
            .sll_family = AF_PACKET,
            .sll_protocol = htons(ETH_P_IP),
            .sll_halen = ETH_ALEN,
            .sll_ifindex = if_index,
        };

        memcpy(&dest2addr.sll_addr, &next_addr,ETH_ALEN);
        int result = sendto(sock2send,buffer,65535,0,(struct sockaddr *)&dest2addr,sizeof(dest2addr)
        if(result = -1)
            printf("wrong send ! \n");
            
        
        
        


    }
}


void init_route_conf()
{
  /*  const char *eth0_addr1 = "192.168.2.0";   // unsure data
    inet_aton(eth0_addr1,inconf[0].ifru_addr);
    const char *eth0_addr2 = "0.0.0.0";    // unsure data;
    inet_aton(eth0_addr2, inconf[0].ifru_broadaddr);
    const char *eth0_addr3 = "eth0";
    inet_aton(eth0_addr3,inconf[0].ifrn_name);
    const char *eth0_addr4 = "255.255.255.0";
    inet_aton(eth0_addr4,inconf[0].ifru_netmask)
    

    const char *eth1_addr1 = "192.168.3.0";   // unsure data
    inet_aton(eth1_addr1,inconf[1].ifru_addr);
    const char *eth1_addr2 = "0.0.0.0";    // unsure data;
    inet_aton(eth1_addr2, inconf[1].ifru_broadaddr);
    const char *eth1_addr3 = "eth1";
    inet_aton(eth1_addr3,inconf[1].ifrn_name);
    const char *eth1_addr4 = "255.255.255.0";
    inet_aton(eth1_addr4,inconf[1].ifru_netmask)
*/
    
}