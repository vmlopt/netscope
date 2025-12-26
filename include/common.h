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

typedef enum {
    SCAN_CONNECT,  // Full TCP connection (default)
    SCAN_SYN,      // TCP SYN scanning (-sS)
    SCAN_IOT       // IoT device scanning (-iot)
} ScanType;

typedef enum {
    IOT_UNKNOWN,
    IOT_CAMERA,
    IOT_ROUTER,
    IOT_DVR,
    IOT_NVR,
    IOT_SMART_TV,
    IOT_SMART_BULB,
    IOT_THERMOSTAT,
    IOT_DOORBELL,
    IOT_PRINTER,
    IOT_NAS,
    IOT_IP_PHONE,
    IOT_WEB_SERVER
} IoTDeviceType;

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
    char status[16];
    long latency_ms;
    char banner[256];
    // Service detection data
    int tcp_window_size;
    long response_time_ms;
    char response_pattern[64];
    char detected_service[128];
    char detected_version[64];
    int confidence_level; // 0-100
    // IoT device data
    IoTDeviceType iot_device_type;
    char iot_device_model[64];
    char iot_vendor[32];
} ScanResult;

extern volatile int running;
extern ScanResult results[MAX_RESULTS];
extern int result_count;
extern OutputFormat output_format;
extern ScanType scan_type;
extern int ports[MAX_PORTS];
extern int port_count;
extern pthread_mutex_t results_mutex;

#endif // COMMON_H
