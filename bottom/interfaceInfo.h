 #ifndef INTERFACEINFO_H
 #define  INTERFACEINFO_H
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/if.h>


// Define a structure to hold interface information
struct InterfaceInfo {
    char name[IFNAMSIZ];  // IFNAMSIZ is the size of interface names
    char description[256];  // Adjust size as needed
    char ip_address[INET6_ADDRSTRLEN];
    char netmask[INET6_ADDRSTRLEN];
    struct InterfaceInfo* next;
};

struct InterfaceInfo *getInterfaces();
void freeInterfaces(struct InterfaceInfo *firstInterface);

 #endif