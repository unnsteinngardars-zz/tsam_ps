#include "syn.h"

/**
 * Constructs a syn scanner object
 * @param s source_ip
 * @param d dest_ip
*/
Syn::Syn(char* s, const char* d){
    strcpy(source_ip, s);
    strcpy(dest_ip, d);
}

sockaddr_in Syn::createSocketAddress(int port){
    struct hostent *server;
    server = gethostbyname(dest_ip);
    struct sockaddr_in saddrin;
    memcpy((char *)&saddrin.sin_addr.s_addr,
        (char *)server->h_addr,
        server->h_length);
    saddrin.sin_family = AF_INET;
    saddrin.sin_port = htons(port);
    return saddrin;
}

/**
 * Create IP header
*/
iphdr* Syn::createIPheader(char* datagram, sockaddr_in& saddrin, int port){
    struct iphdr *IPheader = (struct iphdr *) datagram;
    scan_utilities::setStaticIPheaderData(IPheader);
    IPheader->saddr = inet_addr(source_ip);
    IPheader->daddr = saddrin.sin_addr.s_addr;
    IPheader->check = scan_utilities::csum((unsigned short *) datagram, IPheader->tot_len);
    return IPheader;
}

/**
 * Create TCP header
*/
tcphdr* Syn::createTCPheader(char* datagram, sockaddr_in& saddrin){
    struct tcphdr *TCPheader = (struct tcphdr *) (datagram + sizeof(struct iphdr));
    scan_utilities::setStaticTCPheaderData(TCPheader);
    TCPheader->source = htons(scan_utilities::getRandomSourcePort());
    TCPheader->dest = saddrin.sin_port;         // Dest port
    return TCPheader;
}   

/**
 * Create pseudo header
*/
scan_utilities::pseudo_header Syn::createPseudoHeader(sockaddr_in& saddrin){
    struct scan_utilities::pseudo_header pseudo_header;
    pseudo_header.source = inet_addr(source_ip);
    pseudo_header.dest = saddrin.sin_addr.s_addr;
    pseudo_header.zeroes = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.length = htons(sizeof(struct tcphdr));
    return pseudo_header;
}


/**
 * Gets a vector with well known ports for vulnerabilities
*/
void Syn::setWellKnownPorts(){
    ports = scan_utilities::getKnownPorts();
}

/**
 * Gets a vector of ports from range 1 to max
*/
void Syn::setPortsFromOneToMax(int max){
    ports = scan_utilities::getPorts(max);
}

/**
 * Pop a random port from ports vector
*/
int Syn::popPort(){
    return scan_utilities::getRandomPort(ports);
}

/**
 * check if ports vector is empty
*/
bool Syn::portsEmpty(){
    return ports.empty();
}

/**
 * Scan a port 
*/
bool Syn::scan(int port){
    /* buffers */
    char datagram[DATAGRAM_SIZE];
    
    memset(datagram, 0, DATAGRAM_SIZE);
    int socketfd = scan_utilities::createRawSocket();

    /* create TCP/IP headers */   
    struct sockaddr_in saddrin = createSocketAddress(port);
    struct iphdr *IPheader = createIPheader(datagram,saddrin, port);
    struct tcphdr *TCPheader = createTCPheader(datagram, saddrin);
    struct scan_utilities::pseudo_header pseudo_header = createPseudoHeader(saddrin);
    scan_utilities::applyTCPchecksum(pseudo_header, TCPheader);

    /* send packet */
    if(sendto(socketfd, datagram, IPheader->tot_len, 0, (struct sockaddr *) &saddrin, sizeof(saddrin)) < 0){
        perror("Error sending packet");
        exit(EXIT_FAILURE);
    }

    char receive_buffer[1024];
    memset(receive_buffer, 0, 1024);
    
    /* receive packet */
    if(recv(socketfd, receive_buffer, sizeof(receive_buffer), 0) < 0){
        if(errno != EWOULDBLOCK || errno != EAGAIN){
            perror("Error receiving from host");
            exit(EXIT_FAILURE);
        }
    }

    /* analyze answer */
    struct iphdr *iprcv = (struct iphdr * ) receive_buffer;
    struct tcphdr *tcp_rcv = (struct tcphdr * ) (receive_buffer + iprcv->ihl * 4);
    
    /* create pointer to tcp recieve and access flags */
    int * tcp_ptr = (int * ) tcp_rcv;
    int flags = ntohs(*(tcp_ptr + 3));
    int ack = flags & 0x010;
    int syn = flags & 0x002;

    close(socketfd);
    return ack && syn;
}
