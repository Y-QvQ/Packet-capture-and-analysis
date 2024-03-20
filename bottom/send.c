#include "send.h"

// Function to send packets
void *send_packets(void *args, unsigned char *packet, int send_count,int packet_len)
{
    threadArgs *thread_args = (threadArgs *)args;
    struct ifreq ifr;
    struct sockaddr_ll sll;
    // Create a socket
    int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        perror("socket");
    }

    bzero(&ifr, sizeof(ifr));
    strcpy(ifr.ifr_name, "eth0");
    if (-1 == ioctl(sockfd, SIOCGIFINDEX, &ifr))
    {
        close(sockfd);
        perror("ioctl() SIOCGIFINDEX failed!\n");
    }
    printf("ifr_ifindex = %d\n", ifr.ifr_ifindex);

    bzero(&sll, sizeof(sll));

    // Prepare destination addresss

    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_family = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);

    char dst_ip[16];

    sprintf(dst_ip, "%hhu.%hhu.%hhu.%hhu", thread_args->ip[0], thread_args->ip[1],
            thread_args->ip[2], thread_args->ip[3]);

    // Send packets
    int sent_count = 0;
    while (1)
    {
        int ret = sendto(sockfd, packet, packet_len, 0,
                                    (struct sockaddr *)&sll, sizeof(sll));
        if (ret < 0)
        {
            perror("sendto");
            close(sockfd);
        }
        printf("Sent %d bytes to %s\n", ret, dst_ip);

        // Increment the sent count
        sent_count++;

        // Check if the sent count exceeds the specified limit
        if (send_count != -1 && sent_count >= send_count)
            break;

        // Sleep for 1 second before sending the next packet
        sleep(1);
    }

    // Close socket
    close(sockfd);
}
