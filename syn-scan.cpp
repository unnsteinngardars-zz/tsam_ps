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

struct thread_data_t
{
	int id;
    
};

void* scan(void * arg){

}


int main(int argc, char *argv[])
{     

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;

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

    /* Create vector of hosts, would be possible to read from file */
    // std::vector<std::string> hosts = scan_utilities::getHosts();

    /* Get ports */
    std::vector<int> ports;
    ports.push_back(9929);
    ports.push_back(31337);
    ports.push_back(2323);
    ports.push_back(222);

    
    /* Buffers */
    // The datagram buffer for the total datagram to be sent to host
    char datagram[4096];
    // the tcp checksum buffer
    char* checksum_buffer;
    char receiveBuffer[1024];
    
    /* Zero datagram buffer */    
    memset (datagram, 0, 4096);
    
    /* Declare variables */
    struct sockaddr_in saddrin;
    struct scan_utilities::pseudo_header pseudo_header;


    // char * test = scan_utilities::getLocalIp();
    char source_ip[20];
    char dest_ip[20];

    int source_port = 55555;
    int dest_port = 9929;
    
    strcpy(source_ip, "10.0.2.15");     // hard coded local ip from unnsteinn's ubuntu on VB
    
    strcpy(dest_ip, "45.33.32.156");
    
    /* Configure variables */
    saddrin.sin_family = AF_INET;
    saddrin.sin_port = htons(dest_port);
    saddrin.sin_addr.s_addr = inet_addr(dest_ip);


    /*Construct IP header */
    struct iphdr *IPheader = (struct iphdr *) datagram;
    u_int16_t tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    IPheader->version = 4;                      // Version IPv4
    IPheader->ihl = 5;                          // Header length, int 5 = 20 bytes which is min length.
    IPheader->tos = 0;                          // Type of service
    IPheader->tot_len = tot_len;                // Total length of IP and TCP headers
    IPheader->id = 0;                           // Identification.
    IPheader->frag_off = 0;                     // Fragment offset.
    IPheader->ttl = 255;                        // Time To Live
    IPheader->protocol = IPPROTO_TCP;           // Protocol
    IPheader->saddr = inet_addr(source_ip);     // Source address
    IPheader->daddr = saddrin.sin_addr.s_addr;  // Destination address
    IPheader->check = scan_utilities::csum((unsigned short *) datagram, IPheader->tot_len);


    /*Construct TCP Header */
    struct tcphdr *TCPheader = (struct tcphdr *) (datagram + sizeof (struct iphdr));
    u_int16_t doff = sizeof(struct tcphdr) / 4;
    TCPheader->seq = 0;                         // Sequence number, set to 0 like nmap does.
    TCPheader->ack_seq = 0;                     // Ack number, set to 0 like nmap does
    TCPheader->doff = doff;                     // 5 without options
    TCPheader->syn=1;                           // syn flag
    TCPheader->window = htons (65535);          // Window size, max is 65.535 bytes
    TCPheader->check = 0;                       // Checksum
    TCPheader->urg_ptr = 0;                     // urgent pointer set to 0 like nmap
    // TCPheader->source = htons (source_port);    // Source port
    // TCPheader->dest = saddrin.sin_port;         // Dest port


    /* Construct Pseudo Header */
    pseudo_header.source = inet_addr(source_ip);
    pseudo_header.dest = saddrin.sin_addr.s_addr;
    pseudo_header.zeroes = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.length = htons(sizeof(struct tcphdr));

    printf("PORT\tSTATUS\n");

    // int socketfd = scan_utilities::createRawSocket();

    while(!ports.empty()){
    // for(int port = 20; port < 22; port++){

        /* Configure dynamic properties for datagram */
        int port = ports.back();
        ports.pop_back();

        saddrin.sin_port = htons(port);
        TCPheader->dest = saddrin.sin_port;
        scan_utilities::applyTCPchecksum(pseudo_header, TCPheader);

        /* SCANNING HOST */

        /* Create a file descriptor for sending datagram */

        /* Send Datagram */
        if (sendto(socketfd, datagram, IPheader->tot_len, 0, (struct sockaddr *) &saddrin, sizeof(saddrin)) < 0){
            perror("Error setting IP_HDRINCL");
            exit(EXIT_FAILURE);
        }

        /* Receive Packet */




        // Buffer for receiving data.


        memset (receiveBuffer, 0, 1024);

        if (recv(socketfd, receiveBuffer, sizeof(receiveBuffer), 0) < 0){
            if(errno != EWOULDBLOCK || errno != EAGAIN){
                perror("Error receiving from host");
                exit(EXIT_FAILURE);

            }
            printf("timeout...\n");
        }
        
        struct iphdr * iprcv = (struct iphdr * ) receiveBuffer;
        struct tcphdr * tcp_rcv = (struct tcphdr * ) (receiveBuffer + iprcv->ihl * 4);
        

        int * tcp_ptr = (int * ) tcp_rcv;
        int flags = ntohs(*(tcp_ptr + 3));
        int ack = flags & 0x010;
        int syn = flags & 0x002;

        printf("\n");
        printf("first: 0x%x\n", *(tcp_ptr));
        printf("second: 0x%x\n", *(tcp_ptr + 1));
        printf("third: 0x%x\n", *(tcp_ptr + 2));
        printf("fourth: 0x%x\n", *(tcp_ptr + 3));
        printf("fifth: 0x%x\n", *(tcp_ptr + 4));
        printf("sixth: 0x%x\n", *(tcp_ptr + 5));
        printf("\n");

        printf("ack: %d\n", ack);
        printf("syn: %d\n", syn);


        if (ack && syn) {
            printf("%d\topen\n", port);
        }
        else {
            printf("%d\tclosed\n", port);
        }

        // close(socketfd);

    }



    // close(socketfd);
}
