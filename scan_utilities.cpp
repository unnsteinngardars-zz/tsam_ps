#include "scan_utilities.h"

/**
 * helper function for shuffling ports
*/
int getRand(int i){
    srand(time(NULL));
    return std::rand() % i;
}


/**
 * Get vector of well known vulnerable ports
*/
std::vector<int> scan_utilities::getKnownPorts(){
    std::vector<int> ports = {13, 17, 19, 20, 21, 23, 25, 37, 42, 53, 69, 79,
							  81, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161, 389, 445, 500, 518,
							  520, 587, 635, 669, 1002, 1024, 1025, 1026, 1027, 1028, 1029, 1050, 1103,
							  1296, 1347, 1350, 1417, 1433, 1723, 1863, 2049, 2222, 2251, 2302, 2323,
							  3372, 3389, 3390, 3784, 4444, 4567, 5000, 5050, 5060, 5093, 5351, 5353,
							  5678, 5900, 7000, 7547, 7676, 7938, 8000, 8080, 8082, 8594, 8767, 8888,
							  9000, 9010, 9915, 9916, 9929,9987, 10000, 12203, 12345, 18067, 27374, 27960,
							  27965, 27971, 28786, 28960, 28964, 29070, 29072, 29900, 29901, 29961,
							  30005, 30722, 31337, 34321, 34818};
    return ports;
}

/**
 * Returns vector of hosts scanme.nmap.org and skel.ru.is
 * Used for testing
*/
std::vector<char *> scan_utilities::getHosts(){
    std::vector<char *> hosts;
    hosts.push_back((char * ) "130.208.243.61");
    hosts.push_back((char * )"45.33.32.156");
    // hosts.push_back((char * )"127.0.0.1");
    return hosts;
}

/*
 * Generic checksum calculation function
 * Borrowed from the internet :)
 * https://www.binarytides.com/raw-sockets-c-code-linux/
*/
unsigned short scan_utilities::csum(unsigned short *ptr,int nbytes) 
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
int scan_utilities::createRawSocket(){
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;

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

/**
 * Configure static data for IP header
 * data that does not need to alter between scans
*/
void scan_utilities::setStaticIPheaderData(iphdr*& IPheader){
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

/**
 * Configure static data for TCP header
 * data that does not need to alter between scans
*/
void scan_utilities::setStaticTCPheaderData(tcphdr*& TCPheader){
    u_int16_t doff = sizeof(struct tcphdr) / 4;
    TCPheader->seq = 0;                         // Sequence number, set to 0 like nmap does.
    TCPheader->ack_seq = 0;                     // Ack number, set to 0 like nmap does
    TCPheader->doff = doff;                     // 5 without options
    TCPheader->syn=1;                           // syn flag
    TCPheader->window = htons (65535);          // Window size, max is 65.535 bytes
    TCPheader->check = 0;                       // Checksum
    TCPheader->urg_ptr = 0;                     // urgent pointer set to 0 like nmap
}

/**
 * Apply the checksum for the TCP header
 * @param pseudo_header a pseudo_header used to calculate checksum
 * @param TCPheader the TCP header used
*/
void scan_utilities::applyTCPchecksum(struct pseudo_header& pseudo_header, struct tcphdr *& TCPheader){
    /* get the total size needed for checksum buffer */
    int checksum_buffer_size = sizeof(struct scan_utilities::pseudo_header) + sizeof(struct tcphdr);

    /* allocate memory for checksum buffer */
    char * checksum_buffer = (char *) malloc(checksum_buffer_size);

    /* Insert pseudo header into buffer */
    memcpy(checksum_buffer, (char*)& pseudo_header, sizeof(struct scan_utilities::pseudo_header));
    
    /* Insert TCP header into buffer */
    memcpy(checksum_buffer + sizeof(struct scan_utilities::pseudo_header), TCPheader, sizeof(struct tcphdr));

    /* add the checksum to the TCP header */
    TCPheader->check = scan_utilities::csum((unsigned short *) checksum_buffer, checksum_buffer_size);

    /* Free the allocated memory for the tcp checksum buffer */
    free(checksum_buffer);

}

/**
 * Return random time to sleep in microseconds
*/
int scan_utilities::getRandomTimeInMicroseconds(double min, double max)
{
	std::random_device random_device;
	std::mt19937 mt(random_device());
	std::uniform_real_distribution<double> uid(min, max);
	double random = uid(mt);
	random += 0.5;
	random *= 1000000;
	return (int)random;
}

/**
 * Sets a timer and returns it
*/
time_point scan_utilities::setTimer()
{
	return std::chrono::high_resolution_clock::now();
}

/**
 * Returns the elapsed time in second from start to end
 * @param start time_point object of the start time
 * @param end time_point object of the end time
*/
int scan_utilities::getTimeInSeconds(time_point start, time_point end)
{
	return (int)std::chrono::duration_cast<std::chrono::seconds>(end - start).count();
}

/**
 * remove and return a random port from the given vector
 * @param vector the vector to remove a port from
*/
int scan_utilities::getRandomPort(std::vector<int> &vector)
{
	// Create random integers from 0 to vector.size() - 1;
	std::random_device random_device;
	std::mt19937 mt(random_device());
	std::uniform_int_distribution<int> uid(0, vector.size() - 1);
	// Use the random integer as index to get random element;
	int index = uid(mt);
	int port = vector[index];
	// Remove randomly selected element from vector
	vector.erase(vector.begin() + index);
	// Return the picked port
	return port;
}

/**
 * remove and return a random host from given vector
 * @param vector the vector to remove a host from
*/
std::string scan_utilities::getRandomHost(std::vector<std::string>&vector){
	// Create random integers from 0 to vector.size() - 1;
	std::random_device random_device;
	std::mt19937 mt(random_device());
	std::uniform_int_distribution<int> uid(0, vector.size() - 1);
	// Use the random integer as index to get random element;
	int index = uid(mt);
	std::string host = vector[index];
	// Remove randomly selected element from vector
	vector.erase(vector.begin() + index);
	// Return the picked host
	return host;
}

/**
 * get a random source port from a fixed range
*/
int scan_utilities::getRandomSourcePort(){
    std::random_device random_device;
    std::mt19937 mt(random_device());
    std::uniform_int_distribution<int> uid(444,55555);
    return uid(mt);
}