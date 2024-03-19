#include "arp.h"

arp_hdr *build_arp_request(unsigned char *sender_mac, unsigned char *sender_ip, unsigned char *target_mac, unsigned char *target_ip)
{
       arp_hdr *arp = malloc(sizeof(arp_hdr));
       // 设置 ARP 头部字段
       arp->hardware_type = htons(1);      // 以太网
       arp->protocol_type = htons(0x0800); // IPv4
       arp->hardware_len = 6;              // MAC 地址长度
       arp->protocol_len = 4;              // IP 地址长度
       arp->opcode = htons(2);             // ARP 操作数

       // 设置发送者的 MAC 地址
       memcpy(arp->sender_mac, sender_mac, MAC_ADDR_LEN);

       // 设置发送者的 IP 地址
       memcpy(arp->sender_ip, sender_ip, IPv4_ADDR_LEN);

       // 设置目标的 MAC 地址为广播地址
       memcpy(arp->target_mac, target_mac, MAC_ADDR_LEN);

       // 设置目标的 IP 地址
       memcpy(arp->target_ip, target_ip, IPv4_ADDR_LEN);

       return arp;
}

void send_arp(const char *data)
{
       threadArgs *args = malloc(sizeof(threadArgs));
       if (args == NULL)
       {
              perror("malloc");
              return;
       }
       unsigned char sender_mac[MAC_ADDR_LEN], sender_ip[IPv4_ADDR_LEN], target_mac[MAC_ADDR_LEN], target_ip[IPv4_ADDR_LEN];

       if (sscanf(data, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx %hhu.%hhu.%hhu.%hhu %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx %hhu.%hhu.%hhu.%hhu",
                  &sender_mac[0], &sender_mac[1], &sender_mac[2], &sender_mac[3], &sender_mac[4], &sender_mac[5],
                  &sender_ip[0], &sender_ip[1], &sender_ip[2], &sender_ip[3],
                  &target_mac[0], &target_mac[1], &target_mac[2], &target_mac[3], &target_mac[4], &target_mac[5],
                  &target_ip[0], &target_ip[1], &target_ip[2], &target_ip[3]) != 2 * (MAC_ADDR_LEN + IPv4_ADDR_LEN))
       {
              fprintf(stderr, "Error parsing data\n");
              free(args);
              return;
       }

       eth_hdr *eth = malloc(sizeof(eth_hdr) + sizeof(arp_hdr));
       arp_hdr *arp = build_arp_request(sender_mac, sender_ip, target_mac, target_ip);
       memcpy(eth->src_mac, sender_mac, MAC_ADDR_LEN);
       memcpy(eth->dst_mac, target_mac, MAC_ADDR_LEN);
       eth->eth_type = htons(ETHERTYPE_ARP);
       memcpy((void *)((char *)eth + sizeof(eth_hdr)), arp, sizeof(arp_hdr));

       if (arp == NULL)
       {
              fprintf(stderr, "Error building ARP request\n");
              free(args);
              return;
       }

       memcpy(args->destination_ip, target_ip, IPv4_ADDR_LEN);

       args->destination_port = 21;

       printf("Sending ARP Packet:\n");
       printf("Ethernet Header:\n");
       printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->src_mac[0], eth->src_mac[1], eth->src_mac[2], eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);
       printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2], eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5]);
       printf("Ethernet Type: 0x%04x\n", ntohs(eth->eth_type));

       printf("ARP Header:\n");
       printf("Hardware Type: 0x%04x\n", ntohs(arp->hardware_type));
       printf("Protocol Type: 0x%04x\n", ntohs(arp->protocol_type));
       printf("Hardware Len: %d\n", arp->hardware_len);
       printf("Protocol Len: %d\n", arp->protocol_len);
       printf("Opcode: 0x%04x\n", ntohs(arp->opcode));
       printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2], arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
       printf("Sender IP: %d.%d.%d.%d\n", arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3]);
       printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->target_mac[0], arp->target_mac[1], arp->target_mac[2], arp->target_mac[3], arp->target_mac[4], arp->target_mac[5]);
       printf("Target IP: %d.%d.%d.%d\n", arp->target_ip[0], arp->target_ip[1], arp->target_ip[2], arp->target_ip[3]);

       unsigned char *packet = (unsigned char *)eth;

       send_packets(args, packet, -1,eth_len+arp_len);

       // Free allocated memory
       free(eth);
       free(arp);
       free(args);
}
