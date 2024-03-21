#include "utils.h"

void print_hex(const unsigned char *data, int length)
{
    for (int i = 0; i < length; ++i)
    {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

void swap_data(unsigned char *arg1, unsigned char *arg2, int length)
{
    unsigned char *temp_data = (unsigned char *)malloc(length);
    if (temp_data == NULL)
    {
        fprintf(stderr, "Memory allocation failed.\n");
        return;
    }

    memcpy(temp_data, arg1, length);
    memcpy(arg1, arg2, length);
    memcpy(arg2, temp_data, length);

    free(temp_data);
}


uint16_t calculate_ipv4_checksum(const void *header, size_t len) {
    const uint16_t *buf = header;
    uint32_t sum = 0;
    
    // Sum all 16-bit words
    while (len > 1) {
        sum += *buf++;
        if (sum & 0x80000000)   // Fold 32-bit sum to 16 bits
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    // Add any left-over byte
    if (len)
        sum += *(uint8_t *)buf;

    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // Invert and return checksum
    return ~sum;
}

// Function to calculate the checksum for UDP header
uint16_t calculate_udp_checksum(const void *header, size_t len, const uint8_t *src_addr, const uint8_t *dest_addr) {
    const uint16_t *buf = header;
    uint32_t sum = 0;
    
    // Sum pseudo-header (source address, destination address, UDP length, protocol)
    sum += (src_addr[0] << 8) + src_addr[1];
    sum += (dest_addr[0] << 8) + dest_addr[1];
    sum += 0x0011;  // Protocol (UDP)
    sum += len;

    // Sum UDP header and data
    while (len > 1) {
        sum += *buf++;
        if (sum & 0x80000000)   // Fold 32-bit sum to 16 bits
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    // Add any left-over byte
    if (len)
        sum += *(uint8_t *)buf;

    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // Invert and return checksum
    return ~sum;
}
