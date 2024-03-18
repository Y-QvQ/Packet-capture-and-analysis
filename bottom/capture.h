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

void typeAnalysis(const unsigned char *packet_content, int displayEthernet, int displayHexAscii);
void typeFind(const unsigned char *packet_content);
void typeStatistics(const unsigned char *packet_content);
void packet_handler(const unsigned char *packet, int packet_len, int dealType, int displayEthernet, int displayHexAscii);
void start_capture(const char *interface, char *rule, int dealType, int displayEthernet, int displayHexAscii);
void load_bpf_filter(int sockfd, const char *rule, const char *dev);
#endif