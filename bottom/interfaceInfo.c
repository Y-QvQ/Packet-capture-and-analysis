#include "interfaceInfo.h"

// Function to get interface information
struct InterfaceInfo *getInterfaces() {
    struct InterfaceInfo *firstInterface = NULL;
    struct InterfaceInfo *lastInterface = NULL;

    DIR *dir = opendir("/sys/class/net");
    if (dir == NULL) {
        perror("Error opening /sys/class/net");
        exit(EXIT_FAILURE);
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_LNK) {
            // We assume that network interfaces are symbolic links
            struct InterfaceInfo *interface = malloc(sizeof(struct InterfaceInfo));
            snprintf(interface->name, sizeof(interface->name), "%s", entry->d_name);
            snprintf(interface->description, sizeof(interface->description), "Custom Interface Description");  // You can customize this
            // You can add logic to retrieve IP address and netmask here

            // Add the interface to the linked list
            if (firstInterface == NULL) {
                firstInterface = interface;
                lastInterface = interface;
            } else {
                lastInterface->next = interface;
                lastInterface = interface;
            }
        }
    }

    closedir(dir);

    // Return the first node of the linked list
    return firstInterface;
}

// Function to free the memory allocated for the InterfaceInfo linked list
void freeInterfaces(struct InterfaceInfo *firstInterface) {
    struct InterfaceInfo *current = firstInterface;
    struct InterfaceInfo *next;

    // Traverse the linked list and free each node
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
}
