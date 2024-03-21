#ifndef DNS_H
#define DNS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "../../bottom/send.h"
#include "../../utils.h"

unsigned char *build_dns_response(unsigned char *packet, unsigned char *dns_ip, int *length);
void send_dns(unsigned char *packet,const char *interface,unsigned char *dns_ip);
void typeAttackDNS(const unsigned char *packet_content, const char *interface, char *data);

#endif