#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "../../bottom/send.h"

arp_hdr *build_arp_response(unsigned char *sender_mac, unsigned char *sender_ip, unsigned char *target_mac, unsigned char *target_ip);
void send_arp(const char *data);