#include "filter.h"
struct sock_filter all_code[] = {{0x6, 0, 0, 0x00040000}};
struct sock_filter ip_code[] = {{0x28, 0, 0, 0x0000000c},
                                {0x15, 0, 1, 0x00000800},
                                {0x6, 0, 0, 0x00040000},
                                {0x6, 0, 0, 0x00000000}};
struct sock_filter ipv6_code[] = {{0x28, 0, 0, 0x0000000c},
                                  {0x15, 0, 1, 0x000086dd},
                                  {0x6, 0, 0, 0x00040000},
                                  {0x6, 0, 0, 0x00000000}};
struct sock_filter arp_code[] = {{0x28, 0, 0, 0x0000000c},
                                 {0x15, 0, 1, 0x00000806},
                                 {0x6, 0, 0, 0x00040000},
                                 {0x6, 0, 0, 0x00000000}};
struct sock_filter tcp_code[] = {{0x28, 0, 0, 0x0000000c},
                                 {0x15, 0, 5, 0x000086dd},
                                 {0x30, 0, 0, 0x00000014},
                                 {0x15, 6, 0, 0x00000006},
                                 {0x15, 0, 6, 0x0000002c},
                                 {0x30, 0, 0, 0x00000036},
                                 {0x15, 3, 4, 0x00000006},
                                 {0x15, 0, 3, 0x00000800},
                                 {0x30, 0, 0, 0x00000017},
                                 {0x15, 0, 1, 0x00000006},
                                 {0x6, 0, 0, 0x00040000},
                                 {0x6, 0, 0, 0x00000000}};
struct sock_filter udp_code[] = {{0x28, 0, 0, 0x0000000c},
                                 {0x15, 0, 5, 0x000086dd},
                                 {0x30, 0, 0, 0x00000014},
                                 {0x15, 6, 0, 0x00000011},
                                 {0x15, 0, 6, 0x0000002c},
                                 {0x30, 0, 0, 0x00000036},
                                 {0x15, 3, 4, 0x00000011},
                                 {0x15, 0, 3, 0x00000800},
                                 {0x30, 0, 0, 0x00000017},
                                 {0x15, 0, 1, 0x00000011},
                                 {0x6, 0, 0, 0x00040000},
                                 {0x6, 0, 0, 0x00000000}};
struct sock_filter icmp_code[] = {{0x28, 0, 0, 0x0000000c},
                                  {0x15, 0, 3, 0x00000800},
                                  {0x30, 0, 0, 0x00000017},
                                  {0x15, 0, 1, 0x00000001},
                                  {0x6, 0, 0, 0x00040000},
                                  {0x6, 0, 0, 0x00000000}};
struct sock_filter ip_arp_code[] = {{0x28, 0, 0, 0x0000000c},
                                    {0x15, 2, 0, 0x00000800},
                                    {0x15, 1, 0, 0x000086dd},
                                    {0x15, 0, 1, 0x00000806},
                                    {0x6, 0, 0, 0x00040000},
                                    {0x6, 0, 0, 0x00000000}};

uint32_t ipv4_str_to_hex(const char *ip_str)
{
    struct in_addr ip_addr;

    // Convert the IP address from string to binary form
    if (inet_pton(AF_INET, ip_str, &ip_addr) <= 0)
    {
        perror("inet_pton");
        return 0; // Return 0 for an invalid IP address
    }

    // Return the hexadecimal representation
    return ntohl(ip_addr.s_addr);
}

struct sock_filter *ip_src(uint32_t ip)
{
    struct sock_filter *ip_src_code = malloc(6 * sizeof(struct sock_filter));

    ip_src_code[0] = (struct sock_filter){0x28, 0, 0, 0x0000000c};
    ip_src_code[1] = (struct sock_filter){0x15, 0, 3, 0x00000800};
    ip_src_code[2] = (struct sock_filter){0x20, 0, 0, 0x0000001a};
    ip_src_code[3] = (struct sock_filter){0x15, 0, 1, ip};
    ip_src_code[4] = (struct sock_filter){0x6, 0, 0, 0x00040000};
    ip_src_code[5] = (struct sock_filter){0x6, 0, 0, 0x00000000};

    return ip_src_code;
}

struct sock_filter *ip_dst(uint32_t ip)
{
    struct sock_filter *ip_dst_code = malloc(6 * sizeof(struct sock_filter));

    ip_dst_code[0] = (struct sock_filter){0x28, 0, 0, 0x0000000c};
    ip_dst_code[1] = (struct sock_filter){0x15, 0, 3, 0x00000800};
    ip_dst_code[2] = (struct sock_filter){0x20, 0, 0, 0x0000001e};
    ip_dst_code[3] = (struct sock_filter){0x15, 0, 1, ip};
    ip_dst_code[4] = (struct sock_filter){0x6, 0, 0, 0x00040000};
    ip_dst_code[5] = (struct sock_filter){0x6, 0, 0, 0x00000000};

    return ip_dst_code;
}

void load_bpf_filter(int sockfd, const char *rule, char *dev)
{
    struct sock_fprog bpf_program;
    // struct packet_mreq mreq;

    // printf("%s\n", rule);
    if (strcmp(rule, "all") == 0)
    {
        bpf_program.len = 1;
        bpf_program.filter = all_code;
    }
    else if (strcmp(rule, "ip") == 0)
    {
        bpf_program.len = 4;
        bpf_program.filter = ip_code;
    }
    else if (strcmp(rule, "ip6") == 0)
    {
        bpf_program.len = 4;
        bpf_program.filter = ipv6_code;
    }
    else if (strcmp(rule, "arp") == 0)
    {
        bpf_program.len = 4;
        bpf_program.filter = arp_code;
    }
    else if (strcmp(rule, "tcp") == 0)
    {
        bpf_program.len = 12;
        bpf_program.filter = tcp_code;
    }
    else if (strcmp(rule, "udp") == 0)
    {
        bpf_program.len = 12;
        bpf_program.filter = udp_code;
    }
    else if (strcmp(rule, "icmp") == 0)
    {
        bpf_program.len = 6;
        bpf_program.filter = icmp_code;
    }
    else if (strncmp(rule, "ip src ", 7) == 0)
    {

        const char *ip_str = rule;
        ip_str += 7;
        bpf_program.len = 6;
        bpf_program.filter = ip_src(ipv4_str_to_hex(ip_str));
    }
    else if (strncmp(rule, "ip dst ", 7) == 0)
    {
        const char *ip_str = rule;
        ip_str += 7;
        bpf_program.len = 6;
        bpf_program.filter = ip_dst(ipv4_str_to_hex(ip_str));
    }
    else
    {
        bpf_program.len = 6;
        bpf_program.filter = ip_arp_code;
    }

    // printf("BPF Program:\n");
    // for (int i = 0; i < bpf_program.len; i++)
    // {
    //     printf("[%d] code: %u jt: %u jf: %u k: %u\n", i,
    //            bpf_program.filter[i].code,
    //            bpf_program.filter[i].jt,
    //            bpf_program.filter[i].jf,
    //            bpf_program.filter[i].k);
    // }

    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program)) < 0)
    {
        perror("setsockopt");
        fprintf(stderr, "Error code: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    // memset(&mreq, 0, sizeof(mreq));
    // mreq.mr_type = PACKET_MR_PROMISC;
    // mreq.mr_ifindex = if_nametoindex(dev);

    // if (setsockopt(sockfd, SOL_PACKET,
    //                PACKET_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)))
    // {
    //     perror("setsockopt MR_PROMISC");
    // }
}
