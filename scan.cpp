#include <pthread.h>
#include <sstream>
#include <fstream>
#include <fstream>
#include <iostream>
#include "syn.h"

/* GLOBAL VARIABLES SHARED BY THREADS */
std::vector<std::string>hosts;
static char* source_ip;
static const int MAX_THREADS = 100;

/* mutex for threads */
static pthread_mutex_t lock;
static pthread_mutex_t port_lock;

/**
 * Function for each thread to pop a host from vector and scan it with the selected scanner
*/
void *scan_host(void* arg){

    while(!hosts.empty()){

        if(!hosts.empty()){
            /* mutex before getting host */
            pthread_mutex_lock(&lock);
            const char * host_ip = scan_utilities::getRandomHost(hosts).c_str();
            pthread_mutex_unlock(&lock);
            /* create new syn to scan ports for host */
            Syn *syn = new Syn(source_ip, host_ip);
            syn->setWellKnownPorts();
            while(!syn->portsEmpty()){
                int port = syn->popPort();
                pthread_mutex_lock(&port_lock);
                bool open = syn->scan(port);
                pthread_mutex_unlock(&port_lock);

                if(open){
                    printf("%d\tOPEN\t%s\n", port, host_ip);
                    // printf("%s,%d\n",host_ip, port);
                    // fflush(stdout);
                }
                /* Random sleep before scanning, from 0 to 0.2 seconds in this case */
                double sleeptime = scan_utilities::getRandomTimeInMicroseconds(0, 0.2);
                usleep(sleeptime);
            }
            /* delete syn */
            delete(syn);
        }

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
    if(argc < 3) {
        printf("wrong use: %s <source_ip> <ip_range.txt>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    source_ip = argv[1];

    /* Read ip's from file */  
    std::ifstream file;
    file.open(argv[2]);
    if (!file.is_open()){
        printf("error opening file\n");
    }
    else{
        std::string word;
        while(file >> word){
            hosts.push_back(word);
        }
    }

    /* start timer */
    time_point start = scan_utilities::setTimer();  

    /* initialize variables */
    int NUM_THREADS;
    if (hosts.size() > MAX_THREADS){
        NUM_THREADS = MAX_THREADS;
    }
    else{
	    NUM_THREADS = hosts.size();
    }
    int i;
    
    source_ip = argv[1];
	pthread_t thr[NUM_THREADS];

    printf("PORT\tSTATUS\tHOST\n\n");

    /* Create threads  */
    for (i = 0; i < NUM_THREADS; ++i){
        if(pthread_create(&thr[i], NULL, scan_host, NULL) < 0) {
            perror("Failed to create thread\n");
            exit(EXIT_FAILURE);
        }

    }

    /* Display results header */
    /* Clean up threads */
    for(i = 0; i < NUM_THREADS; ++i){
        pthread_join(thr[i], NULL);
    }

    /* Stop timer and print elapsed time in seconds */
	time_point stop = scan_utilities::setTimer();
	printf("\nExecution time: %d seconds\n", scan_utilities::getTimeInSeconds(start, stop));

}