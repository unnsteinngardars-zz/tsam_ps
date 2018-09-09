#ifndef SYN_H
#define SYN_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <errno.h>
#include <vector>
#include <algorithm>
#include <numeric>
#include <string>
#include <pthread.h>

#include "scan_utilities.h"

static const int DATAGRAM_SIZE = 4096;

class Syn{
    private:
        /* ip's and ports */
        char dest_ip [32];
        char source_ip [32];
        std::vector<int> ports;

        sockaddr_in createSocketAddress(int port);
        iphdr* createIPheader(char* datagram, struct sockaddr_in& saddrin, int port);
        tcphdr* createTCPheader(char* datagram, struct sockaddr_in& saddrin);
        scan_utilities::pseudo_header createPseudoHeader(sockaddr_in& saddrin);

    public:
        /* public methods */
        bool scan(int port);
        int popPort();
        Syn(char* s, const char * d);
        void setWellKnownPorts();
        void setPortsFromOneToMax(int max);
        bool portsEmpty();
};

#endif