USAGE:
    pf [FLAGS] [OPTIONS] [ARGS]

FLAGS:
    -h, --help           Prints help information
    -i, --ignore-case    Regular expression matching ignore case
    -l, --list-device    List device, view device status
    -m, --multiline      Regular expression matching don't do multiline match (do single-line match instead)
    -p, --promisc        Set promiscuous mode on or off. By default, this is on
    -r, --raw            Record raw packet
    -V, --version        Prints version information
    -v, --verb           Verbose mode (-v, -vv, -vvv, etc.)

OPTIONS:
    -x, --amplify <amplify>      Set the package magnification, by default, the package does not do enlargement
                                 processing, and it only takes effect when this parameter is greater than 1 [default: 1]
    -d, --dev <device>           Opens a capture handle for a device [default: ]
    -M, --matcher <matcher>      Specify a BPF filter, only match the target package [default: ]
    -o, --output <output>        Save matched packets in pcap format to pcap file, if there is no matching rule, the
                                 default is to cap the full package [default: /tmp/0.pcap]
    -s, --snap-len <snap-len>    Set the snaplen size (the maximum length of a packet captured into the buffer). Useful
                                 if you only want certain headers, but not the entire packet [default: 65535]

ARGS:
    <pattern>    Specify a regular expression for matching data [default: ]
    <FILE>...    Files is read packet stream from pcap format files