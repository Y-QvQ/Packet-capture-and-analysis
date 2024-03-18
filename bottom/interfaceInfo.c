#include "interfaceInfo.h"

// Function to get interface information
struct InterfaceInfo *getInterfaces()
{
    struct InterfaceInfo *firstInterface = NULL;
    struct InterfaceInfo *lastInterface = NULL;

    DIR *dir = opendir("/sys/class/net");
    if (dir == NULL)
    {
        perror("Error opening /sys/class/net");
        exit(EXIT_FAILURE);
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_type == DT_LNK)
        {
            // We assume that network interfaces are symbolic links
            struct InterfaceInfo *interface = malloc(sizeof(struct InterfaceInfo));
            snprintf(interface->name, sizeof(interface->name), "%.*s", IFNAMSIZ - 1, entry->d_name);
            // snprintf(interface->description, sizeof(interface->description), "Custom Interface Description");

            int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (sockfd < 0)
            {
                perror("Error opening socket");
                exit(EXIT_FAILURE);
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, entry->d_name, sizeof(ifr.ifr_name) - 1);

            if (ioctl(sockfd, SIOCGIFADDR, &ifr) != -1)
            {
                struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
                snprintf(interface->ipAddress, sizeof(interface->ipAddress), "%s", inet_ntoa(addr->sin_addr));
            }

            if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) != -1)
            {
                struct sockaddr_in *mask = (struct sockaddr_in *)&ifr.ifr_netmask;
                snprintf(interface->netmask, sizeof(interface->netmask), "%s", inet_ntoa(mask->sin_addr));
            }

            if (ioctl(sockfd, SIOCGIFBRDADDR, &ifr) != -1)
            {
                struct sockaddr_in *bcast = (struct sockaddr_in *)&ifr.ifr_broadaddr;
                snprintf(interface->broadcast, sizeof(interface->broadcast), "%s", inet_ntoa(bcast->sin_addr));
            }

            close(sockfd);

            // Add the interface to the linked list
            if (firstInterface == NULL)
            {
                firstInterface = interface;
                lastInterface = interface;
            }
            else
            {
                lastInterface->next = interface;
                lastInterface = interface;
            }
        }
    }

    closedir(dir);

    return firstInterface;
}

// Function to free the memory allocated for the InterfaceInfo linked list
void freeInterfaces(struct InterfaceInfo *firstInterface)
{
    struct InterfaceInfo *current = firstInterface;
    struct InterfaceInfo *next;

    // Traverse the linked list and free each node
    while (current != NULL)
    {
        next = current->next;
        free(current);
        current = next;
    }
}

void printAllInterfaces(struct InterfaceInfo *firstInterface)
{
    struct InterfaceInfo *current = firstInterface;

    while (current != NULL)
    {
        printf("Interface Name: %s\n", current->name);
        // printf("Description: %s\n", current->description);
        printf("inet %s\n", current->ipAddress);
        printf("netmask %s\n", current->netmask);
        printf("broadcast %s\n", current->broadcast);
        // printf("inet6 %s\n", current->inet6Address);
        printf("\n");

        current = current->next;
    }
}