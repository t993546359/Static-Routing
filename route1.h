#ifndef STATIC_ROUTE
#define STATIC_ROUTE

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<linux/if_packet.h>
#include<net/ethernet.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netinet/ip_icmp.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdbool.h>

#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <assert.h>
#define macaddr_len 18
#define iface_len 16
#define eth_len 2
#define mac_tbl_len 2
#define arp_tbl_len 2
#define BUF_LEN 65536
struct route_t
{
    struct in_addr dest_addr;
    struct in_addr gateway;
    struct in_addr mask;

    char interface[iface_len]; // #define IFNAMSIZ 8
};


// HWADDR=, 其中 以AA:BB:CC:DD:EE:FF形式的以太网设备的硬件地址
struct device_t // 记录mac地址
{
    char interface[iface_len];
    unsigned char hwaddr [ETH_ALEN]; // define ETH_ALEN 6 {AA : BB : CC : DD : EE :FF }
};

struct arp_t  // 记录主机ip地址和mac地址的对应关系
{
    struct in_addr ip_addr;
    unsigned char hwaddr[ETH_ALEN];
};








// useless part
/*
struct ethhdr
{
    unsigned char h_dest[ETH_ALEN]; //目的MAC地址
     
    unsigned char h_source[ETH_ALEN]; //源MAC地址
     
    __u16 h_proto ; //网络层所使用的协议类型
}__attribute__((packed))  //用于告诉编译器不要对这个结构体中的缝隙部分进行填充操作；

struct in_addr
{
    union
    {
        struct
        {
            u_char s_b1,s_b2,s_b3,s_b4;
        } S_un_b; //An IPv4 address formatted as four u_chars.
        struct
        {
            u_short s_w1,s_w2;
        } S_un_w; //An IPv4 address formatted as two u_shorts
       u_long S_addr;//An IPv4 address formatted as a u_long
    } S_un;
#define s_addr S_un.S_addr
};


struct iphdr {

__u8 tos;//服务类型字段(8位)
__be16 -tot_len;//16位IP数据报总长度
__be16 -id;//16位标识字段（唯一表示主机发送的每一分数据报）
__be16 -frag_off;//(3位分段标志+13位分段偏移数)
__u8 ttl;//8位数据报生存时间
__u8 protocol;//协议字段（8位）
__be16 check;//16位首部校验
__be32 saddr; //源IP地址
__be32 daddr; //目的IP地址
};
struct ifreq
{
#define IFHWADDRLEN 6
 union
 {
  char ifrn_name[IFNAMSIZ];  
 } ifr_ifrn;

 union {
  struct sockaddr ifru_addr;
  struct sockaddr ifru_dstaddr;
  struct sockaddr ifru_broadaddr;
  struct sockaddr ifru_netmask;
  struct  sockaddr ifru_hwaddr;
  short ifru_flags;
  int ifru_ivalue;
  int ifru_mtu;
  struct  ifmap ifru_map;
  char ifru_slave[IFNAMSIZ]; 
  char ifru_newname[IFNAMSIZ];
  void __user * ifru_data;
  struct if_settings ifru_settings;
 } ifr_ifru;
};

#define ifr_name ifr_ifrn.ifrn_name 
#define ifr_hwaddr ifr_ifru.ifru_hwaddr 
#define ifr_addr ifr_ifru.ifru_addr 
#define ifr_dstaddr ifr_ifru.ifru_dstaddr 
#define ifr_broadaddr ifr_ifru.ifru_broadaddr 
#define ifr_netmask ifr_ifru.ifru_netmask 
#define ifr_flags ifr_ifru.ifru_flags 
#define ifr_metric ifr_ifru.ifru_ivalue 
#define ifr_mtu  ifr_ifru.ifru_mtu 
#define ifr_map  ifr_ifru.ifru_map 
#define ifr_slave ifr_ifru.ifru_slave 
#define ifr_data ifr_ifru.ifru_data 
#define ifr_ifindex ifr_ifru.ifru_ivalue 
#define ifr_bandwidth ifr_ifru.ifru_ivalue    
#define ifr_qlen ifr_ifru.ifru_ivalue 
#define ifr_newname ifr_ifru.ifru_newname 
#define ifr_settings ifr_ifru.ifru_settings 


#define eth_len 2*/
#endif