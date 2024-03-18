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
            unsigned char mac[ETH_ALEN];
            if (sscanf(line, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                       &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == ETH_ALEN)
            {
                addNetworkElement(mac);
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
        if (memcmp(current->macAddress, macAddress, ETH_ALEN) == 0)
        {
            return 1; // Discovered
        }
        current = current->next;
    }

    return 0; // Not discovered
}

void addNetworkElement(const unsigned char *macAddress)
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

        memcpy(newElement->macAddress, macAddress, ETH_ALEN);
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
        fprintf(file, "%02X:%02X:%02X:%02X:%02X:%02X\n",
                current->macAddress[0], current->macAddress[1], current->macAddress[2],
                current->macAddress[3], current->macAddress[4], current->macAddress[5]);
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
