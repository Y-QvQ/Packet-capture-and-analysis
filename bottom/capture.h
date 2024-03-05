#ifndef CAPTURE_H
#define CAPTURE_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <unistd.h>

#define BUFSIZE 65536

void packet_handler(const unsigned char *packet, int packet_len, int displayEthernet, int displayHexAscii);
void start_capture(const char *interface, char *rule, int displayEthernet, int displayHexAscii);
void load_bpf_filter(int sockfd, const char *rule, const char *dev);
#endif