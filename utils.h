#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void print_hex(const unsigned char *data, int length);
void swap_data(unsigned char *arg1, unsigned char *arg2, int length);
uint16_t calculate_ipv4_checksum(const void *header, size_t len);
uint16_t calculate_udp_checksum(const void *header, size_t len, const uint8_t *src_addr, const uint8_t *dest_addr);

#endif