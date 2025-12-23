#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>

#define MAX_THREADS 500
#define MAX_RESULTS 10000
#define MAX_PORTS 100
#define TIMEOUT_SEC 0
#define TIMEOUT_USEC 100000 // 100ms timeout
#define DEFAULT_PORT 80

typedef enum {
    OUTPUT_TXT,
    OUTPUT_JSON,
    OUTPUT_CSV
} OutputFormat;

typedef struct {
    int thread_id;
    int *ports;
    int port_count;
    FILE *output_file;
    pthread_mutex_t *file_mutex;
} ThreadData;

typedef struct {
    char ip[16];
    int port;
    char status[8];
    long latency_ms;
    char banner[256];
} ScanResult;

extern volatile int running;
extern ScanResult results[MAX_RESULTS];
extern int result_count;
extern OutputFormat output_format;
extern int ports[MAX_PORTS];
extern int port_count;
extern pthread_mutex_t results_mutex;

#endif // COMMON_H
