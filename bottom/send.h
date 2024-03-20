#ifndef SEND_H
#define SEND_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "../middle/analysis.h"

#define MAX_PACKET_SIZE 1024

// Structure for thread arguments
typedef struct ThreadArgs
{
    u_char mac[6];
    u_char ip[4];
    u_short port;
    struct ThreadArgs *nextArgs;
} threadArgs;


// Function to send packets
void *send_packets(void *args, unsigned char *packet, int send_count,int packet_len);

#endif // SEND_H