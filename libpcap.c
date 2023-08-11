#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>

#define NONE "\e[0m"      // 清除颜色，即之后的打印为正常输出，之前的不受影响
#define YELLOW "\e[1;33m" // 鲜黄
#define L_BLUE "\e[1;34m" // 亮蓝，偏白灰

// 数据包最前面的信息, Mac头部,总长度14字节,然后通过eth_type来解析包后面的内容
typedef struct eth_hdr
{
#define ETHERTYPE_IPv4 (0x0800)
#define ETHERTYPE_IPv6 (0x86DD)
#define ETHERTYPE_ARP (0x0806)

    u_char dst_mac[6]; // 目标mac地址
    u_char src_mac[6]; // 源mac地址
    u_short eth_type;  // 以太网类型:判断数据包协议
} eth_hdr;

// IP头部,总长度20字节,通过protocol判读传输的是什么协议的数据
typedef struct ipv4_hdr
{
#define IPTYPE_ICMP (0x01)
#define IPTYPE_IP (0x04)
#define IPTYPE_TCP (0x06)
#define IPTYPE_UDP (0x11)
    int version : 4;     // 版本
    int header_len : 4;  // 首部长度
    u_char tos : 8;      // 服务类型
    int total_len : 16;  // 总长度
    int ident : 16;      // 标志
    int flags : 16;      // 分片偏移
    u_char ttl : 8;      // 生存时间
    u_char protocol : 8; // 协议：0x01-ICMP;0x06-TCP;0x11-UDP
    int checksum : 16;   // 检验和
    u_char sourceIP[4];  // 源IP地址：通过inet_ntoa()函数转换
    u_char destIP[4];    // 目的IP地址
} ipv4_hdr;

// TCP头部,总长度20字节,通过flags判断是哪种消息
typedef struct tcp_hdr
{
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
    u_short sport;     // 源端口号,通过 ntohs（）转换
    u_short dport;     // 目的端口号
    u_int seq;         // 序列号
    u_int ack;         // 确认号
    u_char head_len;   // 首部长度
    u_char flags;      // 标志位；0x01-FIN,0x02-SYN,0x04-RST,0x08-PSH,0x10-ACK,0x20-URG;
    u_short wind_size; // 16位窗口大小
    u_short check_sum; // 16位TCP检验和
    u_short urg_ptr;   // 16为紧急指针
} tcp_hdr;

// UDP头部,总长度8字节
typedef struct udp_hdr
{
    u_short sport;     // 远端口号
    u_short dport;     // 目的端口号
    u_short tot_len;   // udp头部长度
    u_short check_sum; // 16位udp检验和
} udp_hdr;

// ICMP头部,总长度4字节
typedef struct icmp_hdr
{
    u_char icmp_type; // 类型
    u_char code;      // 代码
    u_short chk_sum;  // 16位检验和
} icmp_hdr;

// IP头部,总长度20
typedef struct ip_hdr
{
    u_int version : 4;    // version(版本)
    u_int header_len : 4; // header length(报头长度)
    u_char tos;
    u_short total_len;
    u_short ident;
    u_short ip_off;
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
} ip_hdr;

// IPv6头部,总长度
typedef struct ipv6_hdr
{
    union
    {
        struct ip6_hdrctl
        {
            u_int32_t ip6_unl_flow; /* 4位的版本，8位的传输与分类，20位的流标识符 */
            u_int16_t ip6_unl_plen; /* 报头长度 */
            u_int8_t ip6_unl_nxt;   /* 下一个报头 */
            u_int8_t ip6_unl_hlim;  /* 跨度限制 */
        } ip6_unl;

        u_int8_t ip6_un2_vfc; /* 4位的版本号，跨度为4位的传输分类 */
    } ip6_ctlun;

#define ip6_vfc ip6_ctlun.ip6_un2_vfc
#define ip6_flow ip6_ctlun.ip6_unl.ip6_unl_flow
#define ip6_plen ip6_ctlun.ip6_unl.ip6_unl_plen
#define ip6_nxt ip6_ctlun.ip6_unl.ip6_unl_nxt
#define ip6_hlim ip6_ctlun.ip6_unl.ip6_unl_hlim
#define ip6_hops ip6_ctlun.ip6_unl.ip6_unl_hops

    struct in6_addr ip6_src; /* 发送端地址 */
    struct in6_addr ip6_dst; /* 接收端地址 */
} ipv6_hdr;

// ARP头部,总长度28
typedef struct arp_hdr
{
    u_int16_t hardware_type; // hardware type
    u_int16_t protocol_type; // protocol type
    u_char hardware_len;     // hardware size
    u_char protocol_len;     // protocol size
    u_int16_t opcode;        // operation code
    u_char sender_mac[6];    // sender MAC address
    u_char sender_ip[4];     // sender IP address
    u_char target_mac[6];    // target MAC address
    u_char target_ip[4];     // target IP address

} arp_hdr;

int eth_len = sizeof(eth_hdr);   // 以太网头的长度
int ipv4_len = sizeof(ipv4_hdr); // ipv4头的长度
int ipv6_len = sizeof(ipv6_hdr); // ipv6头的长度
int arp_len = sizeof(arp_hdr);   // arp头的长度

int ip_len = sizeof(ip_hdr);     // ip头的长度
int tcp_len = sizeof(tcp_hdr);   // tcp头的长度
int udp_len = sizeof(udp_hdr);   // udp头的长度
int icmp_len = sizeof(icmp_hdr); // icmp头的长度

void printHelp();
void getData();
void getInternet(int num_packets, char *ruler);

void printIPv4(const unsigned char *packet_content);
void printICMP(const unsigned char *packet_content);
void printIP(const unsigned char *packet_content);
void printTCP(const unsigned char *packet_content);
void printUDP(const unsigned char *packet_content);

void printIPv6(const unsigned char *packet_content);

void printARP(const unsigned char *packet_content);

int main(int argc, char **argv)
{
    if (argc > 4 || argc == 0)
    {
        printf("usage: ./libpcap -h\n");
        exit(0);
    }
    else if (argv[1][1] == 'h')
    {
        printHelp();
        exit(0);
    }

    printf("%s\n", argv[1]);
    char *ruler;

    switch ((int)argv[1][1]) // 根据参数选择内容
    {
    case 'h':
        printHelp();
        exit(0);

    case 'l': // 获取网络接口名字和掩码等信息
        getData();
        exit(0);

    case 'a': // 以太网数据报捕获
        ruler = NULL;
        break;

    case 'r': // ARP数据包捕获
        ruler = "arp";
        break;

    case 'i': // IP数据包捕获
        ruler = "ip or ip6";
        break;
    case 'm': // ICMP数据包捕获
        ruler = "ip proto 1";
        break;
    case 't': // TCP数据包捕获
        ruler = "ip proto 6";
        break;

    case 'u': // UDP数据包捕获
        ruler = "ip proto 17";
        break;

    default:
        printf("usage: ./libpcap -h\n");
        exit(0);
    }
    getInternet(atoi(argv[3]), ruler);
}

void printHelp()
{
    printf("./libpcap -l   获取网络接口名字和掩码等信息\n");

    printf("./libpcap -a        以太网数据报捕获\n");
    printf("./libpcap -a -n 1   捕获一个数据包\n");
    printf("./libpcap -a -n -1  持续捕获数据包\n");

    printf("./libpcap -r    ARP数据包捕获\n");

    printf("./libpcap -i    IP数据包捕获\n");

    printf("./libpcap -t    TCP数据包捕获\n");

    printf("./libpcap -u    UDP数据包捕获\n");

    printf("./libpcap -m    ICMP数据包捕获\n");
}

void getData()
{
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取可用网络接口列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
    }

    // 遍历链表并打印接口信息
    for (dev = alldevs; dev; dev = dev->next)
    {
        printf("Interface name: %s\n", dev->name);
        printf("Interface description: %s\n", dev->description);

        // 打印接口地址和掩码信息
        pcap_addr_t *addr;
        for (addr = dev->addresses; addr; addr = addr->next)
        {
            if (addr->addr->sa_family == AF_INET)
            { // IPv4地址
                struct sockaddr_in *in_addr = (struct sockaddr_in *)addr->addr;
                struct sockaddr_in *in_mask = (struct sockaddr_in *)addr->netmask;
                char ip_address[INET_ADDRSTRLEN];
                char netmask[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(in_addr->sin_addr), ip_address, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(in_mask->sin_addr), netmask, INET_ADDRSTRLEN);
                printf("IP address: %s\n", ip_address);
                printf("Netmask: %s\n", netmask);
            }
            else if (addr->addr->sa_family == AF_INET6)
            { // IPv6地址
                struct sockaddr_in6 *in6_addr = (struct sockaddr_in6 *)addr->addr;
                struct sockaddr_in6 *in6_mask = (struct sockaddr_in6 *)addr->netmask;
                char ip6_address[INET6_ADDRSTRLEN];
                char netmask6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &(in6_addr->sin6_addr), ip6_address, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &(in6_mask->sin6_addr), netmask6, INET6_ADDRSTRLEN);
                printf("IPv6 address: %s\n", ip6_address);
                printf("Netmask: %s\n", netmask6);
            }
        }

        printf("---------------------------\n");
    }

    // 释放资源
    pcap_freealldevs(alldevs);
}

//回调函数
void packet_handler(unsigned char *argument, const struct pcap_pkthdr *packet_heaher, const unsigned char *packet_content)
{
    unsigned char *mac_string; // mac
    eth_hdr *ethernet_protocol;
    unsigned short ethernet_type; // 以太网类型

    pcap_dump(argument, packet_heaher,packet_content);

    printf("----------------------------------------------------\n");
    printf("%s\n", ctime((time_t *)&(packet_heaher->ts.tv_sec))); // 转换时间
    ethernet_protocol = (eth_hdr *)packet_content;

    mac_string = (unsigned char *)ethernet_protocol->src_mac; // 获取源mac地址
    printf("Mac Source Address is %02x:%02x:%02x:%02x:%02x:%02x\n", *(mac_string + 0), *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

    mac_string = (unsigned char *)ethernet_protocol->dst_mac; // 获取目的mac
    printf("Mac Destination Address is %02x:%02x:%02x:%02x:%02x:%02x\n", *(mac_string + 0), *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

    ethernet_type = ntohs(ethernet_protocol->eth_type); // 获得以太网的类型
    printf("Ethernet type is :%04x\n", ethernet_type);
    switch (ethernet_type)
    {
    case ETHERTYPE_IPv4:
        printIPv4(packet_content);
        break;
    case ETHERTYPE_IPv6:
        printIPv6(packet_content);
        break;
    case ETHERTYPE_ARP:
        printARP(packet_content);
        break;
    default:
        printf("Unkonwn network layer\n");
        break;
    }
}

void getInternet(int num_packets, char *ruler)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    pcap_dumper_t *dumpfile;

    // 获取默认网络接口
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        fprintf(stderr, "Error finding default device: %s\n", errbuf);
    }

    // 打开网络接口以进行数据包捕获
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
    }

    //设置过滤器
    struct bpf_program fcode;
    pcap_compile(handle, &fcode, ruler, 1, 0);
    pcap_setfilter(handle, &fcode);

    //保存文件
    dumpfile = pcap_dump_open(handle, "capture.pcap");
    // 捕获n个数据包
    pcap_loop(handle, num_packets, packet_handler, (unsigned char *)dumpfile);

    // 关闭数据包捕获会话
    pcap_close(handle);
    pcap_dump_close(dumpfile);
}
void printIPv4(const unsigned char *packet_content)
{
    printf("The network layer is " L_BLUE "IPv4" NONE " protocol\n");

    ipv4_hdr *ipv4 = (ipv4_hdr *)(packet_content + eth_len);

    printf("\tip_header_len:%d\n"
           "\tip_len:%d\n",
           ipv4->header_len, ipv4->total_len);

    unsigned char *saddr = (unsigned char *)&ipv4->sourceIP; // 网络字节序转换成主机字节序
    unsigned char *daddr = (unsigned char *)&ipv4->destIP;

    printf("\tsrc_ip:%d.%d.%d.%d\n", saddr[0], saddr[1], saddr[2], saddr[3]); // 源IP地址
    printf("\tdst_ip:%d.%d.%d.%d\n", daddr[0], daddr[1], daddr[2], daddr[3]); // 目的IP地址

    if (ipv4->protocol == IPTYPE_ICMP) // 判断protocol
    {
        printICMP(packet_content);
    }
    else if (ipv4->protocol == IPTYPE_IP)
    {
        printIP(packet_content);
    }
    else if (ipv4->protocol == IPTYPE_TCP)
    {
        printTCP(packet_content);
    }
    else if (ipv4->protocol == IPTYPE_UDP)
    {
        printUDP(packet_content);
    }
    else
    {
        printf("Protocol Unknown\n");
    }
}

void printICMP(const unsigned char *packet_content)
{
    printf("Protocol is " YELLOW "ICMP\n" NONE);

    icmp_hdr *icmp = (icmp_hdr *)(packet_content + eth_len + ipv4_len);

    printf("\ticmp_type = %u\n", icmp->icmp_type);

    for (int i = 0; *(packet_content + eth_len + ipv4_len + icmp_len + i) != '\0'; i++)
    {
        printf("%02x ", *(packet_content + eth_len + ipv4_len + icmp_len + i));

        if (i == 250)
        {
            printf("......");
            break;
        }
    }
    printf("\n");
}
void printTCP(const unsigned char *packet_content)
{
    printf("Protocol is " YELLOW "TCP\n" NONE);

    tcp_hdr *tcp = (tcp_hdr *)(packet_content + eth_len + ipv4_len);
    printf("\ttcp_sport = %u\n", tcp->sport);
    printf("\ttcp_dport = %u\n", tcp->dport);

    switch (tcp->flags)
    {
    case TH_FIN:
        printf("\ttcp_flags:FIN\n");
        break;
    case TH_SYN:
        printf("\ttcp_flags:SYN\n");
        break;
    case TH_ACK:
        printf("\ttcp_flags:ACK\n");
        break;
    case TH_RST:
        printf("\ttcp_flags:RST\n");
        break;
    case TH_PUSH:
        printf("\ttcp_flags:PUSH\n");
        break;
    case TH_URG:
        printf("\ttcp_flags:URG\n");
        break;
    case TH_ECE:
        printf("\ttcp_flags:ECE\n");
        break;
    case TH_CWR:
        printf("\ttcp_flags:CWR\n");
        break;
    default:
        printf("\ttcp_flags:Unkonwn(%u)\n", tcp->flags);
        break;
    }

    for (int i = 0; *(packet_content + eth_len + ipv4_len + tcp_len + i) != '\0'; i++)
    {
        printf("%02x ", *(packet_content + eth_len + ipv4_len + tcp_len + i));

        if (i == 250)
        {
            printf("......");
            break;
        }
    }
    printf("\n");
}
void printUDP(const unsigned char *packet_content)
{
    printf("Protocol is " YELLOW "UDP\n" NONE);

    udp_hdr *udp = (udp_hdr *)(packet_content + eth_len + ipv4_len);
    printf("\tudp_sport = %u\n", udp->sport);
    printf("\tudp_dport = %u\n", udp->dport);

    for (int i = 0; *(packet_content + eth_len + ipv4_len + udp_len + i) != '\0'; i++)
    {
        printf("%02x ", *(packet_content + eth_len + ipv4_len + udp_len + i));

        if (i == 250)
        {
            printf("......");
            break;
        }
    }
    printf("\n");
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

    for (int i = 0; *(packet_content + eth_len + ipv6_len + i) != '\0'; i++)
    {
        printf("%02x ", *(packet_content + eth_len + ipv6_len + i));

        if (i == 250)
        {
            printf("......");
            break;
        }
    }
    printf("\n");
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