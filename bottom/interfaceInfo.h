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
#include <linux/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

struct InterfaceInfo {
    char name[IFNAMSIZ];
    char description[256];
    char ipAddress[INET_ADDRSTRLEN];
    char netmask[INET_ADDRSTRLEN];
    char broadcast[INET_ADDRSTRLEN];
    char inet6Address[INET6_ADDRSTRLEN];
    struct InterfaceInfo *next;
};


struct InterfaceInfo *getInterfaces();
void freeInterfaces(struct InterfaceInfo *firstInterface);
void printAllInterfaces(struct InterfaceInfo *firstInterface);

 #endif