#include "dns.h"

void print_hex(const unsigned char *data, int length)
{
    for (int i = 0; i < length; ++i)
    {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

void swap_data(unsigned char *arg1, unsigned char *arg2, int length)
{
    unsigned char *temp_data = (unsigned char *)malloc(length);
    if (temp_data == NULL)
    {
        fprintf(stderr, "Memory allocation failed.\n");
        return;
    }

    memcpy(temp_data, arg1, length);
    memcpy(arg1, arg2, length);
    memcpy(arg2, temp_data, length);

    free(temp_data);
}

unsigned char *build_dns_response(unsigned char *packet, unsigned char *dns_ip, int *length)
{
    eth_hdr *eth_header = (eth_hdr *)packet;
    swap_data(eth_header->dst_mac, eth_header->src_mac, MAC_ADDR_LEN);
    ipv4_hdr *ip_header = (ipv4_hdr *)(packet + eth_len); // 根据以太网头部长度定位 IP 头部
    swap_data(ip_header->sourceIP, ip_header->destIP, IPv4_ADDR_LEN);
    udp_hdr *udp_header = (udp_hdr *)(packet + eth_len + ipv4_len); // 根据以太网头部长度和 IP 头部长度定位 UDP 头部
    u_short temp = udp_header->sport;
    udp_header->sport = udp_header->dport;
    udp_header->dport = temp;

    // 构建 DNS 头部
    dns_hdr *dns_header = (dns_hdr *)(packet + eth_len + ipv4_len + udp_len);
    dns_header->flags = htons(0x8400); // 设置 DNS 标志，响应报文，不递归查询
    dns_header->an_count = htons(1);   // 设置回答计数

    int dns_name_len = ntohs(udp_header->tot_len) - udp_len - 4; // 计算域名长度
    // 计算报文长度
    int head_len = eth_len + ipv4_len + udp_len + dns_len;
    int old_packet_len = head_len + dns_name_len + sizeof(dns_question);
    int new_packet_len = old_packet_len + dns_name_len + sizeof(dns_answer);
    *length = new_packet_len;
    // 定位到 DNS 请求部分
    dns_question *dns_que = (dns_question *)(packet + head_len + dns_name_len);

    // 分配新的内存来存储响应数据包
    unsigned char *response_packet = (unsigned char *)malloc(new_packet_len);
    if (response_packet == NULL)
    {
        fprintf(stderr, "Memory allocation failed.\n");
        return NULL;
    }

    // 复制原始数据包到新的数据包中
    memcpy(response_packet, packet, old_packet_len);
    memcpy((unsigned char *)response_packet + old_packet_len, (unsigned char *)packet + head_len, dns_name_len);
    // 定位到 DNS 回答部分
    dns_answer *dns_ans = (dns_answer *)((unsigned char *)response_packet + old_packet_len + dns_name_len);

    // 设置 DNS 回答部分的字段
    memcpy(&dns_ans->type, &dns_que->qtype, sizeof(dns_que->qtype));    // 设置查询类型为 A 记录
    memcpy(&dns_ans->class, &dns_que->qclass, sizeof(dns_que->qclass)); // 设置查询类为 IN 类
    dns_ans->ttl = htonl(3600);                                         // 设置生存时间
    dns_ans->rdlength = htons(4);                                       // 设置数据长度为 IPv4 地址长度
    inet_pton(AF_INET, (const char *)dns_ip, &dns_ans->dns_ip);         // 将目标 IP 地址转换为网络字节序

    return response_packet;
}

void send_dns(unsigned char *packet, unsigned char *dns_ip)
{
    int total_len = 0;
    threadArgs *args = malloc(sizeof(threadArgs));
    if (args == NULL)
    {
        fprintf(stderr, "Memory allocation failed.\n");
        return;
    }
    memcpy(args->ip, dns_ip, IPv4_ADDR_LEN);
    unsigned char *response_packet = build_dns_response(packet, dns_ip, &total_len);
    if (response_packet == NULL)
    {
        fprintf(stderr, "Failed to build DNS response packet.\n");
        free(args);
        return;
    }
    
    if (response_packet != NULL)
    {
        printf("Response packet:\n");
        print_hex(response_packet, total_len);
    }

    send_packets(args, response_packet, 3, total_len);

    free(response_packet);
    free(args);
}
