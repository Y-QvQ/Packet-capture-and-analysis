#include "ipdump.h"
#include "bottom/capture.h"
#include "bottom/interfaceInfo.h"
#include "upper/statistics.h"

int main(int argc, char *argv[])
{
    int opt;
    int displayEthernet = 0;
    int displayHexAscii = 0;
    char *interfaceName = NULL;
    char *rule = "";

    struct InterfaceInfo *interfaces = getInterfaces();
    struct InterfaceInfo *current = interfaces;
    interfaceName = current->name;

    while ((opt = getopt(argc, argv, "aedhi:r:")) != -1)
    {
        switch (opt)
        {
        case 'a':
            rule="all";
            break;
        case 'e':
            displayEthernet = 1;
            break;
        case 'd':
            displayHexAscii = 1;
            break;
        case 'h':
            // Display help information (you may want to print a usage message and exit)
            printf("Usage: %s [-aedh] [-i ifrname] [-r rule]\n", argv[0]);
            exit(EXIT_SUCCESS);
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
    //printf("%d %d %s\n", displayEthernet, displayHexAscii,rule);

    start_capture(interfaceName, rule, displayEthernet, displayHexAscii);

    freeInterfaces(interfaces);

    return 0;
}

void printHelp()
{
    printf("./libpcap -l   获取网络接口名字和掩码等信息\n");

    printf("./libpcap -a        以太网数据报捕获\n");
    printf("./libpcap -a -n 1   捕获一个数据包\n");
    printf("./libpcap -a -n -1  持续捕获数据包\n");

    printf("./libpcap -r    ARP数据包捕获\n");

    printf("./libpcap -i    IP数据包捕获\n");

    printf("./libpcap -t    TCP数据包捕获\n");

    printf("./libpcap -u    UDP数据包捕获\n");

    printf("./libpcap -m    ICMP数据包捕获\n");
}