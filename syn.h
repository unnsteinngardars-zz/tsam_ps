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
        /* Socket FD */
        int socketfd;

        /* buffers */
        char datagram[DATAGRAM_SIZE];
        char receive_buffer[DATAGRAM_SIZE];
        char * checksum_buffer;

        /* ip's and ports */
        char dest_ip [32];
        char source_ip [32];
        int source_port = 55555;
        std::vector<int> ports;

        /* structs */   
        struct sockaddr_in saddrin;
        struct scan_utilities::pseudo_header pseudo_header;
        struct iphdr *IPheader;
        struct tcphdr *TCPheader;
        struct iphdr *iprcv;
        struct tcphdr *tcp_rcv;
        struct hostent *server;

        /* private methods */
        void setSockAddrInDestPort(int port);
        void setTCPheaderDestPort(int port);

    public:
        /* public methods */
        void scan();
        Syn(char* s, char * d);
        void setWellKnownPorts();
        void setPortsFromOneToMax(int max);
};

#endif