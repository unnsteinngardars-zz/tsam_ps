#ifndef UTILITIES_H
#define UTILITIES_H

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

#include <vector>
#include <algorithm>

namespace utilities{
    /* struct for the pseudo header, used for TCP checksum */
    struct pseudo_header{
        u_int32_t source;
        u_int32_t dest;
        u_int8_t zeroes;
        u_int8_t protocol;
        u_int16_t length; 
    };
    std::string getLocalIp();
    std::vector<int> getPorts(int size);
    std::vector<std::string> getHosts();
    unsigned short csum(unsigned short *ptr,int nbytes);
    int createRawSocket();
    void setStaticIPheaderData(iphdr*& IPheader);
    void setStaticTCPheaderData(tcphdr*& TCPheader);
    void applyTCPchecksum(utilities::pseudo_header & pseudo_header, tcphdr *& TCPheader);
}

/**
 * NO READY!
 * Read local ip on linux
 * Based on man7.org/linux/man-pages/man3/getifaddrs.3.html
*/
std::string utilities::getLocalIp() {
    struct ifaddrs *ifaddr, *current;
    char buffer[12];
    memset(buffer, 0, 32);
    int family, s,i;
    int LOCAL_IP = 3;
    if(getifaddrs(&ifaddr) < 0){
        perror("getifaddr error");
        exit(0);
    }

    for(current = ifaddr, i = 0; current != NULL; current = current->ifa_next, i++){
        if(current->ifa_addr == NULL){
            continue;
        }
        family = current->ifa_addr->sa_family;

        if(family == AF_INET || family == AF_INET6){
            int size = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
            s = getnameinfo(current->ifa_addr, size, buffer, 15, NULL,0, NI_NUMERICHOST);

            if (s != 0){
                perror("getnameinfo error");
                exit(EXIT_FAILURE);
            }
            if (i == LOCAL_IP) {
                break;
            }
        }
    }
    printf("HOST FOUND: %s\n", buffer);
    freeifaddrs(ifaddr);
    return "";
};

/**
 * Get shuffled ports vector from 1 to size
 * Omitts port 20, 80 and 443
*/
std::vector<int> utilities::getPorts(int size){
    std::vector<int> ports;
    for (int i = 1; i <= size; ++ i){
        if(i != 20 || i != 443 || i != 80){
            ports.push_back(i);
        }
    };
    std::random_shuffle(ports.begin(), ports.end());
    return ports;
}

/**
 * Get hosts, currently from vector
 * but plausible to import from file.
*/
std::vector<std::string> utilities::getHosts(){
    std::vector<std::string> hosts;
    hosts.push_back("130.208.243.61");
    hosts.push_back("45.33.32.156");
    return hosts;
}

/*
 * Generic checksum calculation function
 * Borrowed from the internet :)
 * https://www.binarytides.com/raw-sockets-c-code-linux/
*/
unsigned short utilities::csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}

/**
 * Create a raw socket file descriptor and returns it
 * Sets the IP include header options and configures timeout options
 * In case of error, perror an error message and exit
*/
int utilities::createRawSocket(){
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 220000;

    int socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int one = 1;
    if (setsockopt (socketfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(EXIT_FAILURE);
    }
    if(setsockopt(socketfd,SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0){
        perror("Failed to set timeout options");
        exit(EXIT_FAILURE);
    }
    if (socketfd < 0) {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }
    return socketfd;
}

void utilities::setStaticIPheaderData(iphdr*& IPheader){
    u_int16_t tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    IPheader->version = 4;                      // Version IPv4
    IPheader->ihl = 5;                          // Header length, int 5 = 20 bytes which is min length.
    IPheader->tos = 0;                          // Type of service
    IPheader->tot_len = tot_len;                // Total length of IP and TCP headers
    IPheader->id = 0;                           // Identification.
    IPheader->frag_off = 0;                     // Fragment offset.
    IPheader->ttl = 255;                        // Time To Live
    IPheader->protocol = IPPROTO_TCP;           // Protocol
}

void utilities::setStaticTCPheaderData(tcphdr*& TCPheader){
    u_int16_t doff = sizeof(struct tcphdr) / 4;
    TCPheader->seq = 0;                         // Sequence number, set to 0 like nmap does.
    TCPheader->ack_seq = 0;                     // Ack number, set to 0 like nmap does
    TCPheader->doff = doff;                     // 5 without options
    TCPheader->syn=1;                           // syn flag
    TCPheader->window = htons (65535);          // Window size, max is 65.535 bytes
    TCPheader->check = 0;                       // Checksum
    TCPheader->urg_ptr = 0;                     // urgent pointer set to 0 like nmap
}

void utilities::applyTCPchecksum(utilities::pseudo_header& pseudo_header, tcphdr *& TCPheader){
    /* get the total size needed for checksum buffer */
    int checksum_buffer_size = sizeof(struct utilities::pseudo_header) + sizeof(struct tcphdr);

    /* allocate memory for checksum buffer */
    char * checksum_buffer = (char *) malloc(checksum_buffer_size);

    /* Insert pseudo header into buffer */
    memcpy(checksum_buffer, (char*)& pseudo_header, sizeof(struct utilities::pseudo_header));
    
    /* Insert TCP header into buffer */
    memcpy(checksum_buffer + sizeof(struct utilities::pseudo_header), TCPheader, sizeof(struct tcphdr));

    /* add the checksum to the TCP header */
    // TCPheader->check = utilities::csum((unsigned short *) checksum_buffer, checksum_buffer_size);

    /* Free the allocated memory for the tcp checksum buffer */
    TCPheader->check = utilities::csum((unsigned short *) checksum_buffer, checksum_buffer_size);
    free(checksum_buffer);

}

#endif