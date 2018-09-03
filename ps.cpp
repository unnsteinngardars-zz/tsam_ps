#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <vector>
#include <numeric>
#include <random>
#include <chrono>
// #include <sys/types.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
#include <netdb.h>

void error(const char *msg)
{
	perror(msg);
	exit(0);
}

/* create a socket file descriptor */
void createSocket(int &socketfd)
{
	socketfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (socketfd < 0)
	{
		error("ERROR opening socket");
	}
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
	int random = vector[uid(mt)];
	// Remove randomly selected element from vector
	for (std::vector<int>::iterator it = vector.begin(); it != vector.end(); it++)
	{
		if (*it == random)
		{
			vector.erase(it);
			break;
		}
	}
	return random;
}

int main(int argc, char *argv[])
{
	/* set timer */
	std::chrono::high_resolution_clock::time_point started = std::chrono::high_resolution_clock::now();

	/* List of common ports based on https://bitninja.io/blog/2017/12/21/port-scanning-which-are-most-scanned-ports */
	int commonPorts[31] = {23, 445, 1433, 2323, 110, 669, 8080, 3389, 79, 1350, 81, 5900, 2251, 2222, 139, 1417, 1103, 9000, 5000, 3372, 21, 1347, 42, 7000, 7938, 3390, 17, 1296, 119, 8000, 9010};

	/* VARIABLES */

	/* MIN = 1, MAX = 49151 */
	int MIN_PORT = 1;
	int MAX_PORT = 8000;

	std::vector<int> ports(1000); // ports should take MAX_PORT as argument
	/* create a vector with all ports to be scanned */
	std::iota(ports.begin(), ports.end(), MIN_PORT);

	int socketfd, port, c, closed, open;

	/* counter for closed ports */
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

	/* TCP connect scan */
	while (ports.size() > 0)
	{

		std::chrono::high_resolution_clock::time_point scanstart = std::chrono::high_resolution_clock::now();
		createSocket(socketfd);
		getHostByName(server, host);
		port = getRandomPort(ports);
		populateSocketAddress(server_addr, server, port);
		c = connect(socketfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		if (c >= 0)
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
		if (c < 0)
		{
			std::chrono::high_resolution_clock::time_point scanstop = std::chrono::high_resolution_clock::now();
			printf("Connection time: %d ms\t", (int)std::chrono::duration_cast<std::chrono::milliseconds>(scanstop - scanstart).count());
			printf("Port scanned: %d\n", port);
		}
	}
	printf("\nClosed ports: %d\nOpen ports: %d\n", closed, open);

	/* stop timer */
	std::chrono::high_resolution_clock::time_point done = std::chrono::high_resolution_clock::now();
	printf("Execution time: %d seconds\n", (int)std::chrono::duration_cast<std::chrono::seconds>(done - started).count());
	return 0;
}