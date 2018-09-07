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

/* struct for the pseudo header, used for TCP checksum */
struct pseudo_header{
    u_int32_t source;
    u_int32_t dest;
    u_int8_t zeroes;
    u_int8_t protocol;
    u_int16_t length; 
};

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

/**
 * Create a raw socket file descriptor and returns it
 * In case of error, perror an error message and exit
*/
int createRawSocketFileDescriptor(){
    int socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int one = 1;
    if (setsockopt (socketfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0)
    {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }
    if (socketfd < 0) {
        perror("Failed to create socket");
        exit(1);
    }
    return socketfd;
}


void getSourceIpAddress(){
    struct ifaddrs ** ifa;
    // TODO: implement
}

/**
 * Get shuffled ports vector
*/
std::vector<int> getPorts(int size){
    std::vector<int> ports;
    for (int i = 1; i <= size; ++ i){
        if(i != 20 || i != 443 || i != 80){
            ports.push_back(i);
        }
    };
    std::random_shuffle(ports.begin(), ports.end());
    return ports;
}

std::vector<std::string> getHosts(){
    std::vector<std::string> hosts;
    hosts.push_back("130.208.243.61");
    hosts.push_back("45.33.32.156");
    return hosts;
}

int main(int argc, char *argv[])
{       

    /* Create vector of hosts, would be possible to read from file */
    std::vector<std::string> hosts = getHosts();

    /* Get ports */
    std::vector<int> ports = getPorts(10);

    
    /* Buffers */
    // The datagram buffer for the total datagram to be sent to host
    char datagram[4096];
    // the tcp checksum buffer
    char* checksum_buffer;

    /* Zero datagram buffer */    
    memset (datagram, 0, 4096);
    
    /* Declare variables */
    struct sockaddr_in saddrin;
    struct pseudo_header pseudo_header;

    char source_ip[20], dest_ip[20];

    // char * source_ip =  argv[1];
    // char * dest_ip =  argv[2];

    int source_port = 55555;
    int dest_port = 9929;

    // skel.ru.is = "130.208.243.61"
    // scanme.nmap.org = "45.33.32.156"

    strcpy(source_ip, "10.0.2.15");     // hard coded local ip from unnsteinn's ubuntu on VB
    strcpy(dest_ip, "45.33.32.156");
   
    // strcpy(dest_ip, "130.208.243.61");  
    
    /* Configure variables */
    saddrin.sin_family = AF_INET;
    saddrin.sin_port = htons(dest_port);
    saddrin.sin_addr.s_addr = inet_addr(dest_ip);


    /*Construct IP header WORKS - DO NOT ALTER!*/
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
    IPheader->check = csum((unsigned short *) datagram, IPheader->tot_len);

    /*Construct TCP header WORKS - DO NOT ALTER!*/
    struct tcphdr *TCPheader = (struct tcphdr *) (datagram + sizeof (struct iphdr));
    u_int16_t doff = sizeof(struct tcphdr) / 4;

    TCPheader->source = htons (source_port);    // Source port
    TCPheader->dest = saddrin.sin_port;         // Dest port
    TCPheader->seq = 0;                         // Sequence number, set to 0 like nmap does.
    TCPheader->ack_seq = 0;                     // Ack number, set to 0 like nmap does
    TCPheader->doff = doff;                     // 5 without options
    TCPheader->syn=1;                           // syn flag
    TCPheader->window = htons (65535);          // Window size, max is 65.535 bytes
    TCPheader->check = 0;                       // Checksum
    TCPheader->urg_ptr = 0;                     // urgent pointer set to 0 like nmap

    /* Construct Pseudo Header WORKS - DO NOT ALTER */
    pseudo_header.source = inet_addr(source_ip);
    pseudo_header.dest = saddrin.sin_addr.s_addr;
    pseudo_header.zeroes = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.length = htons(sizeof(struct tcphdr));

    /* get the total size needed for checksum buffer */
    int checksum_buffer_size = sizeof(struct pseudo_header) + sizeof(struct tcphdr);

    /* allocate memory for checksum buffer */
    checksum_buffer = (char *) malloc(checksum_buffer_size);

    /* Insert pseudo header into buffer */
    memcpy(checksum_buffer, (char*)& pseudo_header, sizeof(struct pseudo_header));
    
    /* Insert TCP header into buffer */
    memcpy(checksum_buffer + sizeof(struct pseudo_header), TCPheader, sizeof(struct tcphdr));

    /* add the checksum to the TCP header */
    TCPheader->check = csum((unsigned short *) checksum_buffer, checksum_buffer_size);

    /* Free the allocated memory for the tcp checksum buffer */
    free(checksum_buffer);


    /* SCANNING HOST */

    /* Create a file descriptor for sending datagram */
    int socketfd = createRawSocketFileDescriptor();
    printf("scanning host ip: (%s)\n", inet_ntoa(saddrin.sin_addr));


    /* Send Datagram */
    int c = sendto(socketfd, datagram, IPheader->tot_len, 0, (struct sockaddr *) &saddrin, sizeof(saddrin));
    

    /* Receive Packet */

    // Buffer for receiving data.
    char receiveBuffer[1024];
    memset (receiveBuffer, 0, 1024);
    
    int received = recv(socketfd, receiveBuffer, sizeof(receiveBuffer), 0);

    struct iphdr * iprcv = (struct iphdr * ) receiveBuffer;
    struct tcphdr * tcp_rcv = (struct tcphdr * ) (receiveBuffer + iprcv->ihl * 4);
    

    int * tcp_ptr = (int * ) tcp_rcv;
    int flags = ntohs(*(tcp_ptr + 3));
    int ack = flags & 0x010;
    int syn = flags & 0x002;

    if (ack && syn) {
        printf("port %d open\n", dest_port);
    }
    else {
        printf("port %d closed\n", dest_port);
    }





    // close(socketfd);
}
