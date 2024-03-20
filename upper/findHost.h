#ifndef FIND_HOST_H
#define FIND_HOST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include "../middle/analysis.h"
struct NetworkElement
{
    unsigned char macAddress[MAC_ADDR_LEN];
    unsigned char ipv4Address[IPv4_ADDR_LEN];
    struct NetworkElement *next;
};

void initializeDiscoveredNetworkElements(const char *filename);
int isDiscovered(const unsigned char *macAddress,const unsigned char *ipv4Address);
void addNetworkElement(const unsigned char *macAddress,const unsigned char *ipv4Address);
void printDiscoveredNetworkElementsToFile(const char *filename);
void printDiscoveredNetworkElements();
int getDiscoveredHostCount();

#endif
