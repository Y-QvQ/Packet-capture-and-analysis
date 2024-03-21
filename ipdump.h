#ifndef IPDUMP_H
#define IPDUMP_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include "upper/attack/arp.h"
#include "upper/attack/dns.h"
#include "bottom/capture.h"
#include "bottom/interfaceInfo.h"
#include "upper/statistics.h"

void printHelp();

#endif