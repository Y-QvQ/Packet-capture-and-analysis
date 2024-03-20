#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "../../bottom/send.h"

void swap_data(unsigned char *arg1, unsigned char *arg2, int length);
unsigned char *build_dns_response(unsigned char *packet, unsigned char *dns_ip, int *length);
void send_dns(unsigned char *packet,unsigned char *dns_ip);