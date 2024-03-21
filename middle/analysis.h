#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>

#define NONE "\e[0m"      // 清除颜色，即之后的打印为正常输出，之前的不受影响
#define YELLOW "\e[1;33m" // 鲜黄
#define L_BLUE "\e[1;34m" // 亮蓝，偏白灰

#define MAC_ADDR_LEN 6
#define IPv4_ADDR_LEN 4

// 数据包最前面的信息, Mac头部,总长度14字节,然后通过eth_type来解析包后面的内容
typedef struct eth_hdr
{
    // #define ETHERTYPE_IPv4 (0x0800)
    // #define ETHERTYPE_IPv6 (0x86DD)
    // #define ETHERTYPE_ARP (0x0806)

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
    u_short sport;     // 源端口号
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

typedef struct dns_hdr
{
    u_short id;       // 会话标识符
    u_short flags;    // 标志
    u_short qd_count; // 问题计数
    u_short an_count; // 回答计数
    u_short ns_count; // 权威服务器记录计数
    u_short ar_count; // 附加记录计数
} dns_hdr;

typedef struct dns_question
{
    // char qname[255]; // 查询域名
    u_short qtype;  // 查询类型
    u_short qclass; // 查询类
} dns_question;

typedef struct dns_answer
{
    u_short pname;    // 指向question域名的指针
    u_short type;     // 资源记录类型
    u_short class;    // 资源记录类
    u_char ttl[4];        // 生存时间
    u_short rdlength; // 数据长度
    u_char dns_ip[4]; // 数据
} dns_answer;

extern int eth_len;
extern int ipv4_len;
extern int ipv6_len;
extern int arp_len;
extern int ip_len;
extern int tcp_len;
extern int udp_len;
extern int icmp_len;
extern int dns_len;

char *tcp_ftoa(int flag);

void printEthernet(const unsigned char *packet_content);

void printIPv4(const unsigned char *packet_content);
void printICMP(const unsigned char *packet_content);
void printIP(const unsigned char *packet_content);
void printTCP(const unsigned char *packet_content);
void printUDP(const unsigned char *packet_content);

void printIPv6(const unsigned char *packet_content);

void printARP(const unsigned char *packet_content);

void printData(const unsigned char *packet_content, int length);

#endif