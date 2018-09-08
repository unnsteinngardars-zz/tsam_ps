#include "syn.h"

/**
 * Constructs a syn scanner object
 * @param s source_ip
 * @param d dest_ip
*/
Syn::Syn(char* s, char* d){

    /* configure source and dest */
    server = gethostbyname(d);
    strcpy(source_ip, s);
	memcpy((char *)&saddrin.sin_addr.s_addr,
		   (char *)server->h_addr,
		   server->h_length);
    memset(datagram, 0, DATAGRAM_SIZE);
    
    /* configure saddrin */
    saddrin.sin_family = AF_INET;

    /* configure IP header */
    IPheader = (struct iphdr * ) datagram;
    scan_utilities::setStaticIPheaderData(IPheader);
    IPheader->saddr = inet_addr(s);
    IPheader->daddr = saddrin.sin_addr.s_addr;
    IPheader->check = scan_utilities::csum((unsigned short *) datagram, IPheader->tot_len);

    /* configure TCP header */
    TCPheader = (struct tcphdr*) (datagram + sizeof(struct iphdr));
    scan_utilities::setStaticTCPheaderData(TCPheader);
    TCPheader->source = htons (source_port);    // Source port

    /* configure pseudo header */
    pseudo_header.source = inet_addr(s);
    pseudo_header.dest = saddrin.sin_addr.s_addr;
    pseudo_header.zeroes = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.length = htons(sizeof(struct tcphdr));

    /* open socket */
    socketfd = scan_utilities::createRawSocket();

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
 * Scans the port range 
*/
void Syn::scan(){
    while(!ports.empty()){
        /* sleep for a random interval */
        double sleeptime = scan_utilities::getRandomTimeInMicroseconds(0, 0.2);
        usleep(sleeptime);
        /* get port */
        int port = ports.back();
        ports.pop_back();

        // printf("scanning port: %d\n", port);

        /* configure sockaddr_in and tcp header for fresh sendto attempt */
        setSockAddrInDestPort(port);
        setTCPheaderDestPort(port);
        
        if(sendto(socketfd, datagram, IPheader->tot_len, 0, (struct sockaddr *) &saddrin, sizeof(saddrin)) < 0){
            perror("Error sending packet");
            exit(EXIT_FAILURE);
        }

        /* zero receive buffer */
        memset(receive_buffer, 0, 1024);
        
        /* receive packet */
        if(recv(socketfd, receive_buffer, sizeof(receive_buffer), 0) < 0){
            if(errno != EWOULDBLOCK || errno != EAGAIN){
                perror("Error receiving from host");
                exit(EXIT_FAILURE);
            }
        }

        /* analyze answer */
        iprcv = (struct iphdr * ) receive_buffer;
        tcp_rcv = (struct tcphdr * ) (receive_buffer + iprcv->ihl * 4);
        
        int * tcp_ptr = (int * ) tcp_rcv;
        int flags = ntohs(*(tcp_ptr + 3));
        int ack = flags & 0x010;
        int syn = flags & 0x002;

        /* print result to console, possible to print to file! */
        if (ack && syn) {
            printf("%d\topen\t%s\n", port, inet_ntoa(saddrin.sin_addr));
        }
    }
}

/**
 * Configure the port for the sockaddr_in struct
*/
void Syn::setSockAddrInDestPort(int port) {
    saddrin.sin_port = htons(port);
}

/**
 * Configure the port for the TCPheader
*/
void Syn::setTCPheaderDestPort(int port ){
    TCPheader->dest = port;         // Dest port
}
