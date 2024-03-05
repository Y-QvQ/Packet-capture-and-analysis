#ifndef FILTER_H
#define FILTER_H
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netpacket/packet.h>
#include <net/if.h>

extern struct sock_filter all_code[];
extern struct sock_filter ip_code[];
extern struct sock_filter ipv6_code[];
extern struct sock_filter arp_code[];
extern struct sock_filter tcp_code[];
extern struct sock_filter udp_code[];
extern struct sock_filter icmp_code[];
extern struct sock_filter ip_arp_code[];

uint32_t ipv4_str_to_hex(const char *ip_str);
struct sock_filter *ip_src(uint32_t ip);
struct sock_filter *ip_dst(uint32_t ip);


#endif