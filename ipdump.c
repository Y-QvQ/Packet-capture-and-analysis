#include "ipdump.h"
#include "bottom/capture.h"
#include "bottom/interfaceInfo.h"
#include "upper/statistics.h"

int main(int argc, char *argv[])
{
    int opt;
    int dealType = 0;
    int displayEthernet = 0;
    int displayHexAscii = 0;
    char *interfaceName = NULL;
    char *rule = "";

    struct InterfaceInfo *interfaces = getInterfaces();
    struct InterfaceInfo *current = interfaces;
    interfaceName = current->name;

    while ((opt = getopt(argc, argv, "hlfsaedi:r:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            printHelp();
            exit(EXIT_SUCCESS);
        case 'l':
            printAllInterfaces(current);
            exit(EXIT_SUCCESS);
        case 'f':
            dealType = 1;
            break;
        case 's':
            dealType = 2;
            break;
        case 'a':
            rule = "all";
            break;
        case 'e':
            displayEthernet = 1;
            break;
        case 'd':
            displayHexAscii = 1;
            break;
        case 'i':
            interfaceName = optarg;
            break;
        case 'r':
            rule = optarg;
            break;
        default:
            // Handle invalid arguments or display usage
            fprintf(stderr, "Invalid option: %c\n", opt);
            exit(EXIT_FAILURE);
        }
    }
    // printf("%d %d %s\n", displayEthernet, displayHexAscii,rule);

    start_capture(interfaceName, rule, dealType, displayEthernet, displayHexAscii);

    freeInterfaces(interfaces);

    return 0;
}

void printHelp()
{
    printf("USAGE: ipdump [OPTIONS] [INTERFACE] [RULE]\n\n");
    printf("OPTIONS:\n");
    printf("    -h, --help             Display this help message.\n");
    printf("    -l, --list             List all available network interfaces.\n");
    printf("    -f, --find             Execute network element discovery.\n");
    printf("    -s, --statistics       Display packet statistics.\n");
    printf("    -a, --all              Capture all traffic on the specified interface.\n");
    printf("    -e, --ethernet         Display Ethernet header information.\n");
    printf("    -d, --data             Display raw packet data in hexadecimal and ASCII.\n\n");
    
    printf("INTERFACE:\n");
    printf("    -i, --interface        Specify the network interface to capture traffic.\n");
    printf("                           Example: -i eth0\n\n");

    printf("RULE:\n");
    printf("    -r, --rule             Specify a BPF (Berkeley Packet Filter) rule to filter captured packets.\n");
    printf("                           Available rules:\n");
    printf("                           - all\n");
    printf("                           - ip\n");
    printf("                           - ip6\n");
    printf("                           - arp\n");
    printf("                           - tcp\n");
    printf("                           - udp\n");
    printf("                           - icmp\n");
    printf("                           - ip src [SOURCE_IP]\n");
    printf("                           - ip dst [DESTINATION_IP]\n");
    printf("                           Replace [SOURCE_IP] and [DESTINATION_IP] with valid IP addresses.\n");
    printf("                           Example: -r \"ip src 192.168.1.1\"\n\n");

    printf("EXAMPLES:\n");
    printf("    1. Capture all traffic on eth0 with Ethernet and packet data:\n");
    printf("       ipdump -a -e -d -i eth0\n\n");
    printf("    2. Capture only IPv4 TCP traffic on eth1:\n");
    printf("       ipdump -i eth1 -r tcp\n\n");
    printf("    3. Execute network element discovery:\n");
    printf("       ipdump -f\n\n");
    printf("    4. Display packet statistics:\n");
    printf("       ipdump -s\n\n");
    printf("    5. Display help information:\n");
    printf("       ipdump -h\n\n");
    printf("    6. List all available network interfaces:\n");
    printf("       ipdump -l\n");
}

