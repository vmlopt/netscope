#include "service_detect.h"
#include <string.h>
#include <stdlib.h>

// Service fingerprints database
#define MAX_FINGERPRINTS 50
ServiceFingerprint fingerprints[MAX_FINGERPRINTS];
int fingerprint_count = 0;

void init_service_fingerprints() {
    // Apache HTTP Server fingerprints
    strcpy(fingerprints[fingerprint_count].service_name, "Apache");
    strcpy(fingerprints[fingerprint_count].version_pattern, "2.4.x");
    fingerprints[fingerprint_count].default_port = 80;
    strcpy(fingerprints[fingerprint_count].response_pattern, "Apache/2.4");
    fingerprints[fingerprint_count].min_window_size = 64240;
    fingerprints[fingerprint_count].max_window_size = 65535;
    fingerprints[fingerprint_count].min_response_time = 1;
    fingerprints[fingerprint_count].max_response_time = 50;
    fingerprint_count++;

    strcpy(fingerprints[fingerprint_count].service_name, "Apache");
    strcpy(fingerprints[fingerprint_count].version_pattern, "2.2.x");
    fingerprints[fingerprint_count].default_port = 80;
    strcpy(fingerprints[fingerprint_count].response_pattern, "Apache/2.2");
    fingerprints[fingerprint_count].min_window_size = 58000;
    fingerprints[fingerprint_count].max_window_size = 62000;
    fingerprints[fingerprint_count].min_response_time = 2;
    fingerprints[fingerprint_count].max_response_time = 60;
    fingerprint_count++;

    // OpenSSH fingerprints
    strcpy(fingerprints[fingerprint_count].service_name, "OpenSSH");
    strcpy(fingerprints[fingerprint_count].version_pattern, "8.x");
    fingerprints[fingerprint_count].default_port = 22;
    strcpy(fingerprints[fingerprint_count].response_pattern, "SSH-2.0-OpenSSH_8");
    fingerprints[fingerprint_count].min_window_size = 64240;
    fingerprints[fingerprint_count].max_window_size = 65535;
    fingerprints[fingerprint_count].min_response_time = 1;
    fingerprints[fingerprint_count].max_response_time = 30;
    fingerprint_count++;

    strcpy(fingerprints[fingerprint_count].service_name, "OpenSSH");
    strcpy(fingerprints[fingerprint_count].version_pattern, "7.x");
    fingerprints[fingerprint_count].default_port = 22;
    strcpy(fingerprints[fingerprint_count].response_pattern, "SSH-2.0-OpenSSH_7");
    fingerprints[fingerprint_count].min_window_size = 58000;
    fingerprints[fingerprint_count].max_window_size = 62000;
    fingerprints[fingerprint_count].min_response_time = 2;
    fingerprints[fingerprint_count].max_response_time = 40;
    fingerprint_count++;

    // Nginx fingerprints
    strcpy(fingerprints[fingerprint_count].service_name, "nginx");
    strcpy(fingerprints[fingerprint_count].version_pattern, "1.x");
    fingerprints[fingerprint_count].default_port = 80;
    strcpy(fingerprints[fingerprint_count].response_pattern, "nginx/1.");
    fingerprints[fingerprint_count].min_window_size = 64240;
    fingerprints[fingerprint_count].max_window_size = 65535;
    fingerprints[fingerprint_count].min_response_time = 1;
    fingerprints[fingerprint_count].max_response_time = 25;
    fingerprint_count++;

    // Microsoft IIS fingerprints
    strcpy(fingerprints[fingerprint_count].service_name, "Microsoft-IIS");
    strcpy(fingerprints[fingerprint_count].version_pattern, "10.0");
    fingerprints[fingerprint_count].default_port = 80;
    strcpy(fingerprints[fingerprint_count].response_pattern, "Microsoft-IIS/10.0");
    fingerprints[fingerprint_count].min_window_size = 8192;
    fingerprints[fingerprint_count].max_window_size = 16384;
    fingerprints[fingerprint_count].min_response_time = 5;
    fingerprints[fingerprint_count].max_response_time = 80;
    fingerprint_count++;

    // FTP servers
    strcpy(fingerprints[fingerprint_count].service_name, "vsftpd");
    strcpy(fingerprints[fingerprint_count].version_pattern, "3.x");
    fingerprints[fingerprint_count].default_port = 21;
    strcpy(fingerprints[fingerprint_count].response_pattern, "vsftpd 3.");
    fingerprints[fingerprint_count].min_window_size = 64240;
    fingerprints[fingerprint_count].max_window_size = 65535;
    fingerprints[fingerprint_count].min_response_time = 1;
    fingerprints[fingerprint_count].max_response_time = 20;
    fingerprint_count++;

    // MySQL
    strcpy(fingerprints[fingerprint_count].service_name, "MySQL");
    strcpy(fingerprints[fingerprint_count].version_pattern, "8.x");
    fingerprints[fingerprint_count].default_port = 3306;
    strcpy(fingerprints[fingerprint_count].response_pattern, "");
    fingerprints[fingerprint_count].min_window_size = 64240;
    fingerprints[fingerprint_count].max_window_size = 65535;
    fingerprints[fingerprint_count].min_response_time = 1;
    fingerprints[fingerprint_count].max_response_time = 15;
    fingerprint_count++;

    // PostgreSQL
    strcpy(fingerprints[fingerprint_count].service_name, "PostgreSQL");
    strcpy(fingerprints[fingerprint_count].version_pattern, "13.x");
    fingerprints[fingerprint_count].default_port = 5432;
    strcpy(fingerprints[fingerprint_count].response_pattern, "");
    fingerprints[fingerprint_count].min_window_size = 58000;
    fingerprints[fingerprint_count].max_window_size = 62000;
    fingerprints[fingerprint_count].min_response_time = 2;
    fingerprints[fingerprint_count].max_response_time = 25;
    fingerprint_count++;
}

int match_fingerprint(ScanResult *result, ServiceFingerprint *fp) {
    int score = 0;

    // Check port match (high weight)
    if (result->port == fp->default_port) {
        score += 30;
    }

    // Check banner/response pattern match
    if (strstr(result->banner, fp->response_pattern) != NULL) {
        score += 50;
    }

    // Check TCP window size
    if (result->tcp_window_size >= fp->min_window_size &&
        result->tcp_window_size <= fp->max_window_size) {
        score += 15;
    }

    // Check response time
    if (result->response_time_ms >= fp->min_response_time &&
        result->response_time_ms <= fp->max_response_time) {
        score += 15;
    }

    return score;
}

void detect_service(ScanResult *result) {
    // Initialize service detection database if not already done
    static int initialized = 0;
    if (!initialized) {
        init_service_fingerprints();
        initialized = 1;
    }

    int best_score = 0;
    int best_match = -1;

    // Try to match against all fingerprints
    for (int i = 0; i < fingerprint_count; i++) {
        int score = match_fingerprint(result, &fingerprints[i]);
        if (score > best_score) {
            best_score = score;
            best_match = i;
        }
    }

    // Set detection results
    if (best_match >= 0 && best_score >= 30) { // Minimum confidence threshold
        strcpy(result->detected_service, fingerprints[best_match].service_name);
        strcpy(result->detected_version, fingerprints[best_match].version_pattern);
        result->confidence_level = (best_score > 100) ? 100 : best_score;
    } else {
        strcpy(result->detected_service, "Unknown");
        strcpy(result->detected_version, "");
        result->confidence_level = 0;
    }

    // Extract response pattern for analysis
    if (strlen(result->banner) > 0) {
        // Copy first part of banner as pattern
        size_t copy_len = (strlen(result->banner) < sizeof(result->response_pattern) - 1) ?
                         strlen(result->banner) : sizeof(result->response_pattern) - 1;
        strncpy(result->response_pattern, result->banner, copy_len);
        result->response_pattern[copy_len] = '\0';

        // Truncate at first space or special character for pattern matching
        char *space = strchr(result->response_pattern, ' ');
        if (space) *space = '\0';
        char *slash = strchr(result->response_pattern, '/');
        if (slash && slash != result->response_pattern) {
            *slash = '\0';
        }
    } else {
        strcpy(result->response_pattern, "No banner");
    }
}
