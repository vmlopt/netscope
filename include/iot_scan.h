#ifndef IOT_SCAN_H
#define IOT_SCAN_H

#include "common.h"

// IoT device fingerprint structure
typedef struct {
    IoTDeviceType device_type;
    char vendor[32];
    char model_pattern[64];
    int default_ports[10];  // Common ports for this device type
    int port_count;
    char banner_pattern[128];
    char response_pattern[64];
} IoTDeviceFingerprint;

// IoT scanning functions
void *iot_scanner_thread(void *arg);
int send_iot_syn_packet(int sock, struct sockaddr_in *target, int port);
void detect_iot_device(ScanResult *result);
void init_iot_fingerprints();
IoTDeviceType identify_iot_device(const char *banner, int port);

#endif // IOT_SCAN_H
