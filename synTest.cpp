#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
    /*Raw socket*/
    int rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    /* Packet buffer for headers */
    char datagram[4096];
    /* All zeros */ 
    memset (datagram, 0, 4096);

    
    struct sockaddr_in sin; // todolater


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


    /*TCP header*/
    struct tcphdr *TCPheader = (struct tcphdr *) (datagram + sizeof (struct ip));
    
    TCPheader->source = htons (1234);   // Source port
    TCPheader->dest = htons (80);       // Dest port
    TCPheader->seq = 0;                 // 
    TCPheader->ack_seq = 0;
    TCPheader->doff = 6;                //TCP header size
    TCPheader->fin=0;
    TCPheader->syn=1;
    TCPheader->rst=0;
    TCPheader->psh=0;
    TCPheader->ack=0;
    TCPheader->urg=0;
    TCPheader->window = htons (1024);   // Window size
    TCPheader->check = 0; 
    TCPheader->urg_ptr = 0;
    

}
