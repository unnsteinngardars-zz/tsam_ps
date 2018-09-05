#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include <vector>
#include <numeric>
#include <random>
#include <algorithm>

int NUMBER_OF_PORTS = 5000;

/* global variables */
std::random_device random_device;
std::mt19937 mt(random_device());

/* ports vector */
std::vector<int> ports(NUMBER_OF_PORTS);

/* mutex */
static pthread_mutex_t lock;

/* data structure for threads, keep track of their ID for logging */
typedef struct _thread_data_t
{
	int tid;
} thread_data_t;

/**
 * remove and return a random port from the ports vector
*/
int getRandomPort()
{
	std::uniform_int_distribution<int> uid(0, ports.size() - 1);
	// get a random index into the vector and collect the port
	int index = uid(mt);
	int port = ports[index];
	// Remove randomly selected element from vector
	ports.erase(ports.begin() + index);
	// Return the picked port
	return port;
}

void *scan(void *arg)
{
	thread_data_t *data = (thread_data_t *)arg;
	// While ports is not empty a thread can enter the loop
	int port = 0;
	int index = -1;
	while (!ports.empty())
	{
		// Thread waiting for mutex if another thread is using the ports vector
		pthread_mutex_lock(&lock);
		// A check to ensure that the vector has not changed since the thread entered the loop
		if (!ports.empty())
		{
			port = ports.back();
			ports.pop_back();

			// std::uniform_int_distribution<int> uid(0, ports.size() - 1);
			// index = uid(mt);
			// port = ports[index];
			// ports.erase(ports.begin() + index);
		}
		pthread_mutex_unlock(&lock);
		// If there is a port to be scanned for the current thread, do so
		printf("thread number %d should start scanning port %d\n", data->tid, port);
		// if (port > 0)
		// {
		// 	printf("thread number %d should start scanning port %d\n", data->tid, port);
		// }
	}
	pthread_exit(NULL);
}

int main(int argc, char **argv)
{

	/* INITIALIZE SHARED DATA */
	std::iota(ports.begin(), ports.end(), 1);
	// pthread_mutex_init(&lock, NULL);

	/* Declare variables for main */
	int rc, i;
	int NUM_THREADS = 2;

	pthread_t thr[NUM_THREADS];
	thread_data_t thr_data[NUM_THREADS];

	/* Spawning NUM_THREADS many threads */
	for (i = 0; i < NUM_THREADS; ++i)
	{

		printf("Spawning thread with id %d is ready to scan some ports YO!\n", i);

		/* initialize thread_data for thread with id = i */
		thr_data[i].tid = i;

		/* create a thread,  */
		if ((rc = pthread_create(&thr[i], NULL, scan, &thr_data[i])))
		{
			fprintf(stderr, "error: pthread_create, rc:%d\n", rc);
			return EXIT_FAILURE;
		}
	}

	for (i = 0; i < NUM_THREADS; ++i)
	{
		pthread_join(thr[i], NULL);
		printf("cleaning up thread with id %d\n", i);
	}
	return EXIT_SUCCESS;
}