#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

void error(const char *msg)
{
	perror(msg);
	exit(0);
}

/* create a socket */
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

int main(int argc, char *argv[])
{
	/* variables */
	int MIN_PORT = 1;
	int MAX_PORT = 49151;
	int socketfd, c;

	struct sockaddr_in server_addr;
	struct hostent *server;

	char *host;

	bool printClosed = false;

	/* validate program argument */
	if (argc < 2)
	{
		fprintf(stderr, "usage %s hostname\n", argv[0]);
		exit(0);
	}

	/* grab host from argument */
	host = argv[1];

	for (int i = MIN_PORT; i <= MAX_PORT; ++i)
	{
		createSocket(socketfd);
		getHostByName(server, host);
		populateSocketAddress(server_addr, server, i);
		c = connect(socketfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		if (c >= 0)
		{
			printf("Port: %d\tStatus: Open\n", i);
		}
		else
		{
			if (printClosed)
			{
				printf("Port: %d\tStatus: Closed\n", i);
			}
		}
		close(socketfd);
	}

	return 0;
}