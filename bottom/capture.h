#ifndef CAPTURE_H
#define CAPTURE_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
// #include <net/if.h>
#include <unistd.h>

#include "filter.h"
#include "../middle/analysis.h"
#include "../upper/findHost.h"
#include "../upper/statistics.h"
#include "../upper/attack/dns.h"

#define BUFSIZE 65536

void typeAnalysis(const unsigned char *packet_content, int displayEthernet, int displayHexAscii);
void typeFind(const unsigned char *packet_content);
void typeStatistics(const unsigned char *packet_content);
void packet_handler(const unsigned char *packet,const char *interface, int packet_len, int dealType, int displayEthernet, int displayHexAscii, char *rule);
void start_capture(const char *interface, char *rule, int dealType, int displayEthernet, int displayHexAscii, char *data);
void load_bpf_filter(int sockfd, const char *rule, const char *dev);
#endif