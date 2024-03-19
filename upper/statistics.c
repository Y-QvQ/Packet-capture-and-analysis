#include "statistics.h"
#include "../middle/analysis.h"

// Define counters for various packet types
int totalPackets = 0;
int totalIpPackets = 0;
int totalIpv6Packets = 0;
int totalARPPackets = 0;
int totalTcpPackets = 0;
int totalUdpPackets = 0;
int totalIcmpPackets = 0;
int totalLongFrames = 0;
int totalShortFrames = 0;
int totalIcmpRedirects = 0;
int totalIcmpUnreachable = 0;

// Define start and end times
time_t startTime;
time_t endTime;

// Function to update counters based on packet type
void updateCounters(const unsigned char *packet_content)
{
    totalPackets++;
    int totalLength = 0;
    eth_hdr *ethernet_protocol = (eth_hdr *)packet_content;
    unsigned short ethernet_type = ntohs(ethernet_protocol->eth_type);
    int length = eth_len;

    switch (ethernet_type)
    {
    case ETHERTYPE_IP:
        totalIpPackets++;
        ipv4_hdr *ipv4 = (ipv4_hdr *)(packet_content + length);
        length += ipv4_len;
        totalLength = ipv4->total_len;
        switch (ipv4->protocol)
        {
        case IPTYPE_ICMP:
            totalIcmpPackets++;
            icmp_hdr *icmp = (icmp_hdr *)(packet_content + length);
            length += icmp_len;
            switch (icmp->icmp_type)
            {
            case ICMP_REDIRECT:
                totalIcmpRedirects++;
                break;
            case ICMP_DEST_UNREACH:
                totalIcmpUnreachable++;
                break;
            default:
                printf("ICMP packet with unknown type\n");
                break;
            }
            break;
        case IPTYPE_IP:
            length += ip_len;
            break;
        case IPTYPE_TCP:
            totalTcpPackets++;
            length += tcp_len;
            break;
        case IPTYPE_UDP:
            totalUdpPackets++;
            length += udp_len;
            break;
        }
        break;
    case ETHERTYPE_IPV6:
        totalIpv6Packets++;
        ipv6_hdr *ipv6 = (ipv6_hdr *)(packet_content + length);
        length += ipv6_len;
        totalLength = ipv6->ip6_ctlun.ip6_unl.ip6_unl_plen;
        break;
    case ETHERTYPE_ARP:
        totalARPPackets++;
        arp_hdr *arp = (arp_hdr *)(packet_content + length);
        length += arp_len;
        totalLength = arp->hardware_len + arp->protocol_len;
        break;
    }

    if (totalLength > 1518)
    {
        totalLongFrames++;
    }
    else if (totalLength < 64)
    {
        totalShortFrames++;
    }
}

// Function to set start time
void setStartTime()
{
    startTime = time(NULL);
}

// Function to set end time
void setEndTime()
{
    endTime = time(NULL);
}

// Function to print statistics
void printStatistics()
{
    printf("Start Time: %s", ctime(&startTime));
    printf("End Time: %s", ctime(&endTime));
    printf("Total Duration: %ld seconds\n", endTime - startTime);

    printf("Total Packets: %d\n", totalPackets);
    printf("Total IP Packets: %d (%.2f%%)\n", totalIpPackets, (float)totalIpPackets / totalPackets * 100);
    printf("Total IPv6 Packets: %d (%.2f%%)\n", totalIpv6Packets, (float)totalIpv6Packets / totalPackets * 100);
    printf("Total ARP Packets: %d (%.2f%%)\n", totalARPPackets, (float)totalARPPackets / totalPackets * 100);
    printf("Total TCP Packets: %d (%.2f%% of IP, %.2f%% of Total)\n", totalTcpPackets,
           (float)totalTcpPackets / totalIpPackets * 100, (float)totalTcpPackets / totalPackets * 100);
    printf("Total UDP Packets: %d (%.2f%% of IP, %.2f%% of Total)\n", totalUdpPackets,
           (float)totalUdpPackets / totalIpPackets * 100, (float)totalUdpPackets / totalPackets * 100);
    printf("Total ICMP Packets: %d (%.2f%% of IP, %.2f%% of Total)\n", totalIcmpPackets,
           (float)totalIcmpPackets / totalIpPackets * 100, (float)totalIcmpPackets / totalPackets * 100);
    printf("Total Long Frames: %d (%.2f%% of Total)\n", totalLongFrames, (float)totalLongFrames / totalPackets * 100);
    printf("Total Short Frames: %d (%.2f%% of Total)\n", totalShortFrames, (float)totalShortFrames / totalPackets * 100);
    printf("Total ICMP Redirects: %d\n", totalIcmpRedirects);
    printf("Total ICMP Unreachable: %d\n", totalIcmpUnreachable);
}
