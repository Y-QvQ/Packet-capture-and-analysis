#ifndef FIND_HOST_H
#define FIND_HOST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>

#define MAC_ADDR_LEN 6

struct NetworkElement
{
    unsigned char macAddress[MAC_ADDR_LEN];
    struct NetworkElement *next;
};

void initializeDiscoveredNetworkElements(const char *filename);
int isDiscovered(const unsigned char *macAddress);
void addNetworkElement(const unsigned char *macAddress);
void printDiscoveredNetworkElementsToFile(const char *filename);
void printDiscoveredNetworkElements();
int getDiscoveredHostCount();

#endif
