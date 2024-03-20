#include "capture.h"
#include "filter.h"
#include "../middle/analysis.h"
#include "../upper/findHost.h"
#include "../upper/statistics.h"

void typeAnalysis(const unsigned char *packet_content, int displayEthernet, int displayHexAscii)
{
    eth_hdr *ethernet_protocol = (eth_hdr *)packet_content;
    unsigned short ethernet_type = ntohs(ethernet_protocol->eth_type);
    int length = eth_len;

    if (displayEthernet)
    {
        printEthernet(packet_content);
    }

    switch (ethernet_type)
    {
    case ETHERTYPE_IP:
        printIPv4(packet_content);
        length += ipv4_len;
        ipv4_hdr *ipv4 = (ipv4_hdr *)(packet_content + eth_len);
        switch (ipv4->protocol)
        {
        case IPTYPE_ICMP:
            printICMP(packet_content);
            length += icmp_len;
            break;

        case IPTYPE_IP:
            printIP(packet_content);
            length += ip_len;
            break;

        case IPTYPE_TCP:
            printTCP(packet_content);
            length += tcp_len;
            break;

        case IPTYPE_UDP:
            printUDP(packet_content);
            length += udp_len;
            break;

        default:
            printf("Protocol Unknown\n");
        }
        break;
    case ETHERTYPE_IPV6:
        printIPv6(packet_content);
        length += ipv6_len;
        break;
    case ETHERTYPE_ARP:
        printARP(packet_content);
        length += arp_len;
        break;
    default:
        printf("Unkonwn network layer\n");
        break;
    }

    if (displayHexAscii)
    {
        printData(packet_content, length);
    }
}
void typeFind(const unsigned char *packet_content)
{
    eth_hdr *ethernet_protocol = (eth_hdr *)packet_content;

    if (ntohs(ethernet_protocol->eth_type) == ETHERTYPE_IP)
    {
        ipv4_hdr *ipv4 = (ipv4_hdr *)(packet_content + eth_len);
        initializeDiscoveredNetworkElements("findHost.txt");
        addNetworkElement(ethernet_protocol->src_mac, ipv4->sourceIP);
        addNetworkElement(ethernet_protocol->dst_mac, ipv4->destIP);

        printDiscoveredNetworkElementsToFile("findHost.txt");
        printDiscoveredNetworkElements();
    }
}
void typeStatistics(const unsigned char *packet_content)
{
    setEndTime();
    updateCounters(packet_content);
    printStatistics();
}
void packet_handler(const unsigned char *packet_content, int packet_len, int dealType, int displayEthernet, int displayHexAscii)
{
    printf("----------------------------------------------------\n");

    switch (dealType)
    {
    case 0:
        typeAnalysis(packet_content, displayEthernet, displayHexAscii);
        break;
    case 1:
        typeFind(packet_content);
        break;
    case 2:
        typeStatistics(packet_content);
        break;
    default:
        fprintf(stderr, "Invalid dealType: %d\n", dealType);
        exit(EXIT_FAILURE);
        break;
    }
}

void start_capture(const char *interface, char *rule, int dealType, int displayEthernet, int displayHexAscii)
{
    int sockfd;
    struct sockaddr_ll sa;
    socklen_t sa_len = sizeof(sa);
    unsigned char buffer[BUFSIZE]; // Use a constant or macro for buffer size

    // Open a raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to the specified interface
    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_nametoindex(interface);
    if (bind(sockfd, (struct sockaddr *)&sa, sa_len) < 0)
    {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // BPF filter
    load_bpf_filter(sockfd, rule, interface);

    // struct sock_fprog bpf_program;
    // struct sock_filter udp_code[] = {{0x28, 0, 0, 0x0000000c},
    //                              {0x15, 0, 5, 0x000086dd},
    //                              {0x30, 0, 0, 0x00000014},
    //                              {0x15, 6, 0, 0x00000011},
    //                              {0x15, 0, 6, 0x0000002c},
    //                              {0x30, 0, 0, 0x00000036},
    //                              {0x15, 3, 4, 0x00000011},
    //                              {0x15, 0, 3, 0x00000800},
    //                              {0x30, 0, 0, 0x00000017},
    //                              {0x15, 0, 1, 0x00000011},
    //                              {0x6, 0, 0, 0x00040000},
    //                              {0x6, 0, 0, 0x00000000}};
    // bpf_program.len = 12;
    // bpf_program.filter = udp_code;
    // if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program)) < 0)
    // {
    //     perror("setsockopt");
    //     fprintf(stderr, "Error code: %d\n", errno);
    //     exit(EXIT_FAILURE);
    // }

    setStartTime();
    // Start capturing packets (loop until interrupted)
    while (1)
    {
        int packet_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&sa, &sa_len);
        if (packet_len < 0)
        {
            perror("recvfrom");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        // Call the packet handler
        packet_handler(buffer, packet_len, dealType, displayEthernet, displayHexAscii);
    }

    // Close the socket (may not be reached in an infinite loop)
    close(sockfd);
}
