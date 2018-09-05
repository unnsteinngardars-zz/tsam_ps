#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>


/*
    Generic checksum calculation function
    Borrowed from the internet :)
    https://www.binarytides.com/raw-sockets-c-code-linux/
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
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

struct PseudoHeader{
    u_int32_t source;
    u_int32_t dest;
    u_int8_t zeroes;
    u_int8_t protocol;
    u_int16_t length; 
};

int main(int argc, char *argv[])
{
    /* Create a raw socket file descriptor
    *  use IPPROTO_RAW to prevent using the IP_HDRINCL options
    */
    int socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    /* Display error and exit if the socket was not successfully created */
    if (socketfd < 0) {
        perror("Failed to create socket");
        exit(1);
    }

    /* Buffers */

    // The datagram buffer for the total datagram to be sent to host
    char datagram[4096];
    // pseudo header buffer for TCP pseudo header used for the tcp checksum
    struct PseudoHeader pseudoHeader;
    // the tcp checksum buffer
    char* TCPchecksumBuffer;
    
    /* Zero IP buffer */    
    memset (datagram, 0, 4096);
    
    /* Populate socket address structure */
    struct sockaddr_in saddrin;
    saddrin.sin_family = AF_INET;
    saddrin.sin_port = htons(8888);
    saddrin.sin_addr.s_addr = inet_addr("127.0.0.1");

    /*IP header*/
    struct iphdr *IPheader = (struct iphdr *) datagram;
    
    IPheader->ihl = 5;          // Header length
    IPheader->version = 4;      // Version IPv4
    IPheader->tos = 0;          // Type of service
    IPheader->tot_len = sizeof (struct iphdr) + sizeof(struct tcphdr);       // Total length
    IPheader->id = htonl(54321);// Identification SKOÐA
    IPheader->frag_off = 0;     // Fragment offset field
    IPheader->ttl = 64;         // TimeToLive
    IPheader->protocol = 6;     // Protocol
    IPheader->check = 0;        // Checksum
    IPheader->saddr = inet_addr("127.0.0.1");   // Source address 
    IPheader->daddr = inet_addr("127.0.0.1");   // Destination address

    IPheader->check = csum((unsigned short *) datagram, IPheader->tot_len);

    /*TCP header*/
    struct tcphdr *TCPheader = (struct tcphdr *) (datagram + sizeof (struct ip));
    
    TCPheader->source = htons (1234);   // Source port
    TCPheader->dest = htons (80);       // Dest port
    TCPheader->seq = 0;                 // 
    TCPheader->ack_seq = 0;
    TCPheader->doff = 5;                //TCP header size
    TCPheader->fin=0;
    TCPheader->syn=1;
    TCPheader->rst=0;
    TCPheader->psh=0;
    TCPheader->ack=0;
    TCPheader->urg=0;
    TCPheader->window = htons (1024);   // Window size
    TCPheader->check = 0; 
    TCPheader->urg_ptr = 0;

    pseudoHeader.source = inet_addr("127.0.0.1");
    pseudoHeader.dest = inet_addr("127.0.0.1");
    pseudoHeader.zeroes = 0;
    pseudoHeader.protocol = IPPROTO_TCP;
    pseudoHeader.length = htons(sizeof(struct tcphdr));

    /* get the total size needed for checksum buffer */
    int checkSumSize = sizeof(struct PseudoHeader) + sizeof(struct tcphdr);
    /* allocate memory for checksum buffer */
    TCPchecksumBuffer = (char *) malloc(checkSumSize);

    /* Insert PseudoHeader into buffer */
    memcpy(TCPchecksumBuffer, (char*)& pseudoHeader, sizeof(struct PseudoHeader));
    /* Insert TCP header into buffer */
    memcpy(TCPchecksumBuffer + sizeof(struct PseudoHeader), TCPheader, sizeof(struct tcphdr));
    
    TCPheader->check = csum((unsigned short *) TCPchecksumBuffer, checkSumSize);

    /* Free the allocated memory for the tcp checksum buffer */
    free(TCPchecksumBuffer);

    // int one = 1;
    // const int *val = &one;
    // if (setsockopt(socketfd, IPPROTO_TCP, IP_HDRINCL, val, sizeof(one)) < 0) {
    //     perror("Error setting IP_HDRINCL options");
    //     exit(0);
    // }

    /* Send TCP */
    int c = sendto(socketfd, datagram, IPheader->tot_len, 0, (struct sockaddr *) &saddrin, sizeof(saddrin));
    close(socketfd);
    printf("c: %d\n", c);
}
