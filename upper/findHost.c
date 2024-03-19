#include "findHost.h"

struct NetworkElement *discoveredNetworkElements = NULL;

void initializeDiscoveredNetworkElements(const char *filename)
{
    discoveredNetworkElements = NULL;

    // Read existing entries from the file
    FILE *file = fopen(filename, "r");

    if (file != NULL)
    {
        char line[18]; // Assuming MAC address format like "01:23:45:67:89:AB"

        while (fgets(line, sizeof(line), file) != NULL)
        {
            unsigned char mac[MAC_ADDR_LEN];
            unsigned char ipv4[IPv4_ADDR_LEN];
if (sscanf(line, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx %hhu.%hhu.%hhu.%hhu",
                       &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5],
                       &ipv4[0], &ipv4[1], &ipv4[2], &ipv4[3]) == MAC_ADDR_LEN + IPv4_ADDR_LEN)
            {
                addNetworkElement(mac, ipv4);
            }
        }

        fclose(file);
    }
}

int isDiscovered(const unsigned char *macAddress)
{
    struct NetworkElement *current = discoveredNetworkElements;

    while (current != NULL)
    {
        if (memcmp(current->macAddress, macAddress, MAC_ADDR_LEN) == 0)
        {
            return 1; // Discovered
        }
        current = current->next;
    }

    return 0; // Not discovered
}

void addNetworkElement(const unsigned char *macAddress, const unsigned char *ipv4Address)
{
    // Check if the MAC address is already discovered
    if (!isDiscovered(macAddress))
    {
        struct NetworkElement *newElement = malloc(sizeof(struct NetworkElement));
        if (newElement == NULL)
        {
            perror("Memory allocation failed");
            exit(EXIT_FAILURE);
        }

        memcpy(newElement->macAddress, macAddress, MAC_ADDR_LEN);
        memcpy(newElement->ipv4Address, ipv4Address, IPv4_ADDR_LEN);
        newElement->next = discoveredNetworkElements;
        discoveredNetworkElements = newElement;
    }
}

void printDiscoveredNetworkElementsToFile(const char *filename)
{
    FILE *file = fopen(filename, "w"); // Open file in append mode

    if (file == NULL)
    {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    struct NetworkElement *current = discoveredNetworkElements;

    while (current != NULL)
    {
        fprintf(file, "%02X:%02X:%02X:%02X:%02X:%02X ",
                current->macAddress[0], current->macAddress[1], current->macAddress[2],
                current->macAddress[3], current->macAddress[4], current->macAddress[5]);
        fprintf(file, "%d.%d.%d.%d\n",
                current->ipv4Address[0], current->ipv4Address[1], current->ipv4Address[2], current->ipv4Address[3]);

        current = current->next;
    }

    fclose(file);
}

void printDiscoveredNetworkElements()
{
    struct NetworkElement *current = discoveredNetworkElements;

    while (current != NULL)
    {
        printf("Discovered MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               current->macAddress[0], current->macAddress[1], current->macAddress[2],
               current->macAddress[3], current->macAddress[4], current->macAddress[5]);
        printf("Discovered IP: %d.%d.%d.%d\n\n",
               current->ipv4Address[0], current->ipv4Address[1], current->ipv4Address[2], current->ipv4Address[3]);
        current = current->next;
    }
    printf("Host Count:%d\n", getDiscoveredHostCount());
}

int getDiscoveredHostCount()
{
    int count = 0;
    struct NetworkElement *current = discoveredNetworkElements;

    while (current != NULL)
    {
        count++;
        current = current->next;
    }

    return count;
}
