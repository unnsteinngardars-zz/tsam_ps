#include <pthread.h>
#include "syn.h"

/* GLOBAL VARIABLES SHARED BY THREADS */
std::vector<char * >hosts;
static char* source_ip;

/* mutex for threads */
static pthread_mutex_t lock;
static pthread_mutex_t port_lock;

/**
 * Function for each thread to pop a host from vector and scan it with the selected scanner
*/
void *scan_host(void* arg){

    char* host_ip;

    pthread_mutex_lock(&lock);
    host_ip = hosts.back();
    hosts.pop_back();
    pthread_mutex_unlock(&lock);
    
    /* Create scanner of type syn */
    /* Ideally here the scanner would be chosen based on input from user */

    Syn syn(source_ip, host_ip);
    syn.setWellKnownPorts();
    while(!syn.portsEmpty()){
        int port = syn.popPort();
        pthread_mutex_lock(&port_lock);
        bool open = syn.scan(port);
        pthread_mutex_unlock(&port_lock);

        if(open){
            printf("%d\topen\t%s\n", port, host_ip);
        }

        /* Random sleep before scanning, from 0 to 0.2 seconds in this case */
        double sleeptime = scan_utilities::getRandomTimeInMicroseconds(0, 0.2);
        usleep(sleeptime);
    }
    

    /* thread finishing up */
    pthread_exit(NULL);
}


/**
 * Main enterance for port scanner
 * Long term goal was to read a range if IP's from a file
 * 
 * @author Unnsteinn Gardarsson & Asdis Erna Gudmundsdottir
*/
int main(int argc, char *argv[])
{   
    /* Validate arguments */
    if(argc < 2) {
        printf("wrong use: %s <source_ip>", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    /* start timer */
    time_point start = scan_utilities::setTimer();  
    hosts = scan_utilities::getHosts();

    /* initialize variables */
	int NUM_THREADS = hosts.size();
    int i;
    
    source_ip = argv[1];

	pthread_t thr[NUM_THREADS];

    /* Create threads  */
    for (i = 0; i < NUM_THREADS; ++i){
        if(pthread_create(&thr[i], NULL, scan_host, NULL) < 0) {
            perror("Failed to create thread\n");
            exit(EXIT_FAILURE);
        }

    }

    /* Display results header */
    printf("PORT\tSTATUS\tHOST\n");

    /* Clean up threads */
    for(i = 0; i < NUM_THREADS; ++i){
        pthread_join(thr[i], NULL);
    }

    /* Stop timer and print elapsed time in seconds */
	time_point stop = scan_utilities::setTimer();
	printf("\nExecution time: %d seconds\n", scan_utilities::getTimeInSeconds(start, stop));

}