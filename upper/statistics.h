 #ifndef STATISTICS_H
 #define  STATISTICS_H
#include <stdio.h>
#include <time.h>

void updateCounters(const unsigned char *packet_content);
void setStartTime();
void setEndTime();
void printStatistics();

 #endif