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