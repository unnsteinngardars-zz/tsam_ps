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
#include "utilities.h"

struct thread_data_t
{
	int id;
};

void* scan(void * arg){

}


int main(int argc, char *argv[])
{     

    /* Create vector of hosts, would be possible to read from file */
    std::vector<std::string> hosts = utilities::getHosts();

    /* Get ports */
    std::vector<int> ports = utilities::getPorts(10);

    
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
    struct utilities::pseudo_header pseudo_header;

    /* Thread variables */
    int NUM_THREADS = 20;
    static pthread_mutex_t lock;
	pthread_t thr[NUM_THREADS];
	thread_data_t thr_data[NUM_THREADS];

    // char * source_ip = utilities::getLocalIp();
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
    utilities::setStaticIPheaderData(IPheader);
    IPheader->saddr = inet_addr(source_ip);     // Source address
    IPheader->daddr = saddrin.sin_addr.s_addr;  // Destination address
    IPheader->check = utilities::csum((unsigned short *) datagram, IPheader->tot_len);


    /*Construct TCP Header */
    struct tcphdr *TCPheader = (struct tcphdr *) (datagram + sizeof (struct iphdr));
    utilities::setStaticTCPheaderData(TCPheader);
    TCPheader->source = htons (source_port);    // Source port
    TCPheader->dest = saddrin.sin_port;         // Dest port


    /* Construct Pseudo Header */
    pseudo_header.source = inet_addr(source_ip);
    pseudo_header.dest = saddrin.sin_addr.s_addr;
    pseudo_header.zeroes = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.length = htons(sizeof(struct tcphdr));

    printf("PORT\tSTATUS\n");
    for(int port = 9929; port < 9940; port++){

        /* Configure dynamic properties for datagram */
        saddrin.sin_port = htons(port);
        TCPheader->dest = saddrin.sin_port;
        utilities::applyTCPchecksum(pseudo_header, TCPheader);

        /* SCANNING HOST */

        /* Create a file descriptor for sending datagram */
        int socketfd = utilities::createRawSocket();

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
        }
        
        struct iphdr * iprcv = (struct iphdr * ) receiveBuffer;
        struct tcphdr * tcp_rcv = (struct tcphdr * ) (receiveBuffer + iprcv->ihl * 4);
        

        int * tcp_ptr = (int * ) tcp_rcv;
        int flags = ntohs(*(tcp_ptr + 3));
        int ack = flags & 0x010;
        int syn = flags & 0x002;

        if (ack && syn) {
            printf("%d\topen\n", port);
        }
        else {
            printf("%d\tclosed\n", port);
        }

    }



    // close(socketfd);
}
