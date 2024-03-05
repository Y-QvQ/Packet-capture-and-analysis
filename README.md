### Options:

- `-h, --help`: Display this help message.
- `-l, --list`: List all available network interfaces.
- `-f, --find`: Execute network element discovery.
- `-s, --statistics`: Display packet statistics.
      ifconfig eth1 promisc
      ifconfig eth1 -promisc
- `-a, --all`: Capture all traffic on the specified interface.
- `-e, --ethernet`: Display Ethernet header information.
- `-d, --data`: Display raw packet data in hexadecimal and ASCII.

### Interface:

- `-i, --interface`: Specify the network interface to capture traffic.
  Example: `-i eth0`

### Rule:

- `-r, --rule`: Specify a BPF (Berkeley Packet Filter) rule to filter captured packets.
  Available rules:
  - all
  - ip
  - ip6
  - arp
  - tcp
  - udp
  - icmp
  - ip src [SOURCE_IP]
  - ip dst [DESTINATION_IP]
    Replace [SOURCE_IP] and [DESTINATION_IP] with valid IP addresses.
    Example: `-r "ip src 192.168.1.1"`

### Examples:

1. Capture all traffic on eth0 with Ethernet and packet data:
   ipdump -a -e -d -i eth0

2. Capture only IPv4 TCP traffic on eth1:
   ipdump -i eth1 -r tcp

3. Execute network element discovery:
   ipdump -f

4. Display packet statistics:
   ipdump -s


5. Display help information:
   ipdump -h

6. List all available network interfaces:
   ipdump -l