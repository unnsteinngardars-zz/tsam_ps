#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <vector>
#include <algorithm>
#include <random>
#include <chrono>
#include <thread>
#include <unistd.h>
#include <netdb.h>

typedef std::chrono::high_resolution_clock::time_point time_point;

/**
 * Create socket
*/
int createSocket()
{
	// AF_INET address family for IPv4
	// SOCK_STREAM indicates TCP communication
	// IPPROTO_TCP TCP protocol
	int socketfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (socketfd < 0)
	{
		perror("Error creating socket");
		exit(EXIT_FAILURE);
	}
	return socketfd;
}

/* resolve host */
void getHostByName(hostent *&server, char *host)
{
	server = gethostbyname(host);
	if (server == NULL)
	{
		perror("Error, no such host");
		exit(EXIT_FAILURE);
	}
}

/**
 * Populate sockaddr_in structure
*/
void populateSocketAddress(sockaddr_in &address, hostent *&server, int port)
{
	address.sin_family = AF_INET;
	memcpy((char *)&address.sin_addr.s_addr,
		   (char *)server->h_addr,
		   server->h_length);
	address.sin_port = htons(port);
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

	/* A vector with 101 commonly open and vulnerable ports */

	std::vector<int> ports = {13, 17, 19, 20, 21, 23, 25, 37, 42, 53, 69, 79,
							  81, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161, 389, 445, 500, 518,
							  520, 587, 635, 669, 1002, 1024, 1025, 1026, 1027, 1028, 1029, 1050, 1103,
							  1296, 1347, 1350, 1417, 1433, 1723, 1863, 2049, 2222, 2251, 2302, 2323,
							  3372, 3389, 3390, 3784, 4444, 4567, 5000, 5050, 5060, 5093, 5351, 5353,
							  5678, 5900, 7000, 7547, 7676, 7938, 8000, 8080, 8082, 8594, 8767, 8888,
							  9000, 9010, 9915, 9916, 9987, 10000, 12203, 12345, 18067, 27374, 27960,
							  27965, 27971, 28786, 28960, 28964, 29070, 29072, 29900, 29901, 29961,
							  30005, 30722, 34321, 34818};

	int socketfd, port, c, closed, open;

	/* counter for closed and open ports */
	closed = 0;
	open = 0;

	/* structs for establishing connections to host */
	struct sockaddr_in server_addr;
	struct hostent *server;

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
		socketfd = createSocket();
		int port = ports.back();
		ports.pop_back();
		printf("scanning port %d\n", port);
			// port = getRandomPort(ports);
		populateSocketAddress(server_addr, server, port);
		c = connect(socketfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
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
		close(socketfd);
	}
	printf("\nClosed ports: %d\nOpen ports: %d\n", closed, open);

	/* stop timer */
	time_point stop = setTimer();
	printf("Execution time: %d seconds\n", getTimeInSeconds(start, stop));
	return 0;
}