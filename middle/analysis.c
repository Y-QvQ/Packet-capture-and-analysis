#include "analysis.h"

int eth_len = sizeof(eth_hdr);   // 以太网头的长度
int ipv4_len = sizeof(ipv4_hdr); // ipv4头的长度
int ipv6_len = sizeof(ipv6_hdr); // ipv6头的长度
int arp_len = sizeof(arp_hdr);   // arp头的长度

int ip_len = sizeof(ip_hdr);     // ip头的长度
int tcp_len = sizeof(tcp_hdr);   // tcp头的长度
int udp_len = sizeof(udp_hdr);   // udp头的长度
int icmp_len = sizeof(icmp_hdr); // icmp头的长度

char *tcp_ftoa(int flag)
{
  static int  f[] = {'U', 'A', 'P', 'R', 'S', 'F'}; 
#define TCP_FLG_MAX (sizeof f / sizeof f[0])
  static char str[TCP_FLG_MAX + 1];           
  unsigned int mask = 1 << (TCP_FLG_MAX - 1); 
  int i;                                     
 
  for (i = 0; i < TCP_FLG_MAX; i++) {
    if (((flag << i) & mask) != 0)
      str[i] = f[i];
    else
      str[i] = '0';
  }
  str[i] = '\0';
 
  return str;
}


void printEthernet(const unsigned char *packet_content)
{
    unsigned char *mac_string; // mac
    eth_hdr *ethernet_protocol;
    unsigned short ethernet_type; // 以太网类型

    ethernet_protocol = (eth_hdr *)packet_content;

    mac_string = (unsigned char *)ethernet_protocol->src_mac; // 获取源mac地址
    printf("Mac Source Address is %02x:%02x:%02x:%02x:%02x:%02x\n", *(mac_string + 0), *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

    mac_string = (unsigned char *)ethernet_protocol->dst_mac; // 获取目的mac
    printf("Mac Destination Address is %02x:%02x:%02x:%02x:%02x:%02x\n", *(mac_string + 0), *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

    ethernet_type = ntohs(ethernet_protocol->eth_type); // 获得以太网的类型
    printf("Ethernet type is :%04x\n", ethernet_type);

}


void printIPv4(const unsigned char *packet_content)
{
    printf("The network layer is " L_BLUE "IPv4" NONE " protocol\n");

    ipv4_hdr *ipv4 = (ipv4_hdr *)(packet_content + eth_len);

    printf("\tip_header_len: %d\n"
           "\tip_len: %d\n"
           "\tip_tos: 0x%x\n"
           "\tip_flags: 0x%x\n",
           ipv4->header_len, ipv4->total_len, ipv4->tos, ipv4->flags);

    unsigned char *saddr = (unsigned char *)&ipv4->sourceIP; // 网络字节序转换成主机字节序
    unsigned char *daddr = (unsigned char *)&ipv4->destIP;

    printf("\tsrc_ip:%d.%d.%d.%d\n", saddr[0], saddr[1], saddr[2], saddr[3]); // 源IP地址
    printf("\tdst_ip:%d.%d.%d.%d\n", daddr[0], daddr[1], daddr[2], daddr[3]); // 目的IP地址

}

void printICMP(const unsigned char *packet_content)
{
    printf("Protocol is " YELLOW "ICMP\n" NONE);

    icmp_hdr *icmp = (icmp_hdr *)(packet_content + eth_len + ipv4_len);

    printf("\ticmp_type = %u\n", icmp->icmp_type);

}

void printTCP(const unsigned char *packet_content)
{
    printf("Protocol is " YELLOW "TCP\n" NONE);

    tcp_hdr *tcp = (tcp_hdr *)(packet_content + eth_len + ipv4_len);
    printf("\ttcp_sport = %u\n", tcp->sport);
    printf("\ttcp_dport = %u\n", tcp->dport);

    printf("\ttcp_flags:%s\n",tcp_ftoa(tcp->flags));

    // switch (tcp->flags)
    // {
    // case TH_FIN:
    //      printf("\ttcp_flags:FIN\n");
    //     break;
    // case TH_SYN:
    //     printf("\ttcp_flags:SYN\n");
    //     break;
    // case TH_ACK:
    //     printf("\ttcp_flags:ACK\n");
    //     break;
    // case TH_RST:
    //     printf("\ttcp_flags:RST\n");
    //     break;
    // case TH_PUSH:
    //     printf("\ttcp_flags:PUSH\n");
    //     break;
    // case TH_URG:
    //     printf("\ttcp_flags:URG\n");
    //     break;
    // case TH_ECE:
    //     printf("\ttcp_flags:ECE\n");
    //     break;
    // case TH_CWR:
    //     printf("\ttcp_flags:CWR\n");
    //     break;
    // default:
    //     printf("\ttcp_flags:Unkonwn(%u)\n", tcp->flags);
    //     break;
    // }

}
void printUDP(const unsigned char *packet_content)
{
    printf("Protocol is " YELLOW "UDP\n" NONE);

    udp_hdr *udp = (udp_hdr *)(packet_content + eth_len + ipv4_len);
    printf("\tudp_sport = %u\n", udp->sport);
    printf("\tudp_dport = %u\n", udp->dport);

}
void printIP(const unsigned char *packet_content)
{
    printf("Protocol is IP\n");
}

void printIPv6(const unsigned char *packet_content)
{
    printf("The network layer is " L_BLUE "IPv6" NONE " protocol\n");

    ipv6_hdr *ipv6 = (ipv6_hdr *)(packet_content + eth_len);

    struct sockaddr_in6 *in6_addr_src = (struct sockaddr_in6 *)&ipv6->ip6_src;
    struct sockaddr_in6 *in6_addr_dst = (struct sockaddr_in6 *)&ipv6->ip6_dst;
    char ip6_address_src[INET6_ADDRSTRLEN];
    char ip6_address_dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(in6_addr_src->sin6_addr), ip6_address_src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(in6_addr_dst->sin6_addr), ip6_address_dst, INET6_ADDRSTRLEN);

    printf("\tversion           : %x\r\n"
           "\ttraffic class     : %x\r\n"
           "\tflow label        : %x\r\n"
           "\tpayload length    : %x\r\n"
           "\tnext header       : %x\r\n"
           "\thop limit         : %x\r\n"
           "\tsource            : %s\r\n"
           "\tdestination       : %s\r\n",
           ipv6->ip6_ctlun.ip6_un2_vfc,
           ipv6->ip6_ctlun.ip6_unl.ip6_unl_flow,
           ipv6->ip6_ctlun.ip6_unl.ip6_unl_flow,
           ipv6->ip6_ctlun.ip6_unl.ip6_unl_plen,
           ipv6->ip6_ctlun.ip6_unl.ip6_unl_nxt,
           ipv6->ip6_ctlun.ip6_unl.ip6_unl_hlim,
           ip6_address_src,
           ip6_address_dst);

}

void printARP(const unsigned char *packet_content)
{
    printf("The network layer is " L_BLUE "ARP" NONE " protocol\n");

    arp_hdr *arp = (arp_hdr *)(packet_content + eth_len);

    printf("\thardware_type:%I16u\n"
           "\tprotocol_type:%I16u\n",
           arp->hardware_type, arp->protocol_type);

    unsigned char *mac_string;
    mac_string = (unsigned char *)arp->sender_mac; // 获取sender mac地址
    printf("\tSender MAC Address is %02x:%02x:%02x:%02x:%02x:%02x\n", *(mac_string + 0), *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

    mac_string = (unsigned char *)arp->target_mac; // 获取target mac
    printf("\tTarget MAC Address is %02x:%02x:%02x:%02x:%02x:%02x\n", *(mac_string + 0), *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

    printf("\tsrc_ip:%d.%d.%d.%d\n", arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3]);
    printf("\tdst_ip:%d.%d.%d.%d\n", arp->target_ip[0], arp->target_ip[1], arp->target_ip[2], arp->target_ip[3]);
}


void printData(const unsigned char *packet_content,int length){
    for (int i = 0; *(packet_content + length + i) != '\0'; i++)
    {
        printf("%02x ", *(packet_content + length + i));

        // if (i == 250)
        // {
        //     printf("......");
        //     break;
        // }
    }
    printf("\n");
}