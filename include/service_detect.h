#ifndef SERVICE_DETECT_H
#define SERVICE_DETECT_H

#include "common.h"

// Service fingerprint structure
typedef struct {
    char service_name[64];
    char version_pattern[64];
    int default_port;
    char response_pattern[128];
    int min_window_size;
    int max_window_size;
    long min_response_time;
    long max_response_time;
} ServiceFingerprint;

// Function declarations
void detect_service(ScanResult *result);
int match_fingerprint(ScanResult *result, ServiceFingerprint *fp);
void init_service_fingerprints();

#endif // SERVICE_DETECT_H
