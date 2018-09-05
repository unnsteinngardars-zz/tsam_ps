#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <vector>
#include <numeric>
#include <random>
#include <chrono>
#include <thread>
#include <unistd.h>
// #include <sys/types.h>
// #include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>


using namespace std;
typedef std::chrono::high_resolution_clock::time_point time_point;

void error(const char *msg)
{
	perror(msg);
	exit(0);
}

/* Create and return a raw socket file descriptor */
int createRawSocket()
{
	// AF_INET address family for IPv4
	// SOCK_STREAM indicates TCP communication
	// IPPROTO_TCP TCP protocol
	int rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (rawfd < 0)
	{
		error("ERROR opening socket");
	}
	return rawfd;
}

/* resolve host */
void getHostByName(hostent *&server, char *host)
{
	server = gethostbyname(host);
	if (server == NULL)
	{
		error("ERROR, no such host");
	}
}

/* populate sockaddr_in data structure */
void populateSocketAddress(sockaddr_in &address, hostent *&server, int port)
{
	address.sin_family = AF_INET;
	memcpy((char *)&address.sin_addr.s_addr,
		   (char *)server->h_addr,
		   server->h_length);
	address.sin_port = htons(port);
}

/**
 * remove and return a random port from the given vector
 * @param vector the vector to remove a port from
*/
int getRandomPort(std::vector<int> &vector)
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

time_point setTimer()
{
	return std::chrono::high_resolution_clock::now();
}

int getTimeInSeconds(time_point start, time_point end)
{
	return (int)std::chrono::duration_cast<std::chrono::seconds>(end - start).count();
}

/**
 * Return random time to sleep in microseconds
*/
int getRandomTime(double min, double max)
{
	std::random_device random_device;
	std::mt19937 mt(random_device());
	std::uniform_real_distribution<double> uid(min, max);
	double random = uid(mt);
	random += 0.5;
	random *= 1000000;
	return (int)random;
}

int main(int argc, char *argv[])
{
	/* set timer */
	time_point start = setTimer();

	/* VARIABLES */

	/* MIN = 1, MAX = 49151 */
	int MIN_PORT = 1;
	int MAX_PORT = 1023;

	/* A vector with 101 commonly open and vulnerable ports */

	// std::vector<int> ports = {13, 17, 19, 20, 21, 23, 25, 37, 42, 53, 69, 79,
	// 						  81, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161, 389, 445, 500, 518,
	// 						  520, 587, 635, 669, 1002, 1024, 1025, 1026, 1027, 1028, 1029, 1050, 1103,
	// 						  1296, 1347, 1350, 1417, 1433, 1723, 1863, 2049, 2222, 2251, 2302, 2323,
	// 						  3372, 3389, 3390, 3784, 4444, 4567, 5000, 5050, 5060, 5093, 5351, 5353,
	// 						  5678, 5900, 7000, 7547, 7676, 7938, 8000, 8080, 8082, 8594, 8767, 8888,
	// 						  9000, 9010, 9915, 9916, 9987, 10000, 12203, 12345, 18067, 27374, 27960,
	// 						  27965, 27971, 28786, 28960, 28964, 29070, 29072, 29900, 29901, 29961,
	// 						  30005, 30722, 34321, 34818};

	std::vector<int> ports(10);
	std::iota(ports.begin(), ports.end(), MIN_PORT);

	int rawfd, port, c, closed, open;

	/* counter for closed and open ports */
	closed = 0;
	open = 0;

	/* structs for establishing connections to host */
	struct sockaddr_in server_addr;
	struct hostent *server;

    char packetBuffer[4096];

    /* structs for IP and TCH headers */
    struct ip *IPheader = (struct ip *) packetBuffer;
    struct tcphdr *TCPheader = (struct tcphdr *) (packetBuffer + sizeof (struct ip));
	
    
    IPheader->ip_hl = 5;    // Header length
    IPheader->ip_v = 4;     // Version IPv4
    IPheader->ip_tos;       // Type of service
    IPheader->ip_len;       // Total length
    IPheader->ip_id;        // Identification
    IPheader->ip_off;       // Fragment offset field
    IPheader->ip_ttl;       // TimeToLive
    IPheader->ip_p;         // Protocol
    IPheader->ip_sum;       // Checksum
    IPheader->ip_src.s_addr;// Source address = inet_addr("123.0.0.1"); // ATHUGA
    IPheader->ip_dst.s_addr;// Destination address
    
    
    /* validate program argument */
	if (argc < 2)
	{
		fprintf(stderr, "usage %s hostname\n", argv[0]);
		exit(0);
	}

	/* grab host from argument */
	char *host = argv[1];

	printf("Scanning open ports for host %s\n\n", host);
	printf("PORT\tSTATE\n");

	getHostByName(server, host);

	/* TCP connect scan */
	while (ports.size() > 0)
	{
		int randomTime = getRandomTime(0, 0.2);
		usleep(randomTime);
		rawfd = createRawSocket();
		port = getRandomPort(ports);
		populateSocketAddress(server_addr, server, port);
		c = connect(rawfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		if (c == 0)
		{
			printf("%d\tOpen\n", port);
			open++;
		}
		else
		{
			// printf("%d\tClosed\n", port);
			closed++;
		}
		close(rawfd);
	}
	printf("\nClosed ports: %d\nOpen ports: %d\n", closed, open);

	/* stop timer */
	time_point stop = setTimer();
	printf("Execution time: %d seconds\n", getTimeInSeconds(start, stop));
	return 0;
}