#ifndef SCAN_UTILITIES_H
#define SCAN_UTILITIES_H

#include <string.h>
#include <string>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <ctime>
#include <chrono>
#include <vector>
#include <algorithm>

typedef std::chrono::high_resolution_clock::time_point time_point;

namespace scan_utilities{
    /* struct for the pseudo header, used for TCP checksum */
    struct pseudo_header{
        u_int32_t source;
        u_int32_t dest;
        u_int8_t zeroes;
        u_int8_t protocol;
        u_int16_t length; 
    };

    // char * getLocalIp(); // Not working
    std::vector<int> getPorts(int size);
    std::vector<int> getKnownPorts();
    std::vector<char *> getHosts();
    unsigned short csum(unsigned short *ptr,int nbytes);
    int createRawSocket();
    void setStaticIPheaderData(iphdr*& IPheader);
    void setStaticTCPheaderData(tcphdr*& TCPheader);
    void applyTCPchecksum(struct pseudo_header & pseudo_header, tcphdr *& TCPheader);
    int getRandomTimeInMicroseconds(double min, double max);
    time_point setTimer();
    int getTimeInSeconds(time_point start, time_point end);
    int getRandomPort(std::vector<int>& vector);
    std::string getRandomHost(std::vector<std::string>& vector);
    int getRandomSourcePort();
}

#endif