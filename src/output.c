#include "output.h"
#include <stdio.h>
#include <string.h>

void export_txt(ScanResult *results, int count, const char *filename) {
    char full_path[256];
    snprintf(full_path, sizeof(full_path), "./out/%s", filename);
    FILE *file = fopen(full_path, "a");
    if (!file) return;

    for (int i = 0; i < count; i++) {
        fprintf(file, "%s\t%d\t%s\t%ld\t%s\t%d\t%ld\t%s\t%s %s\t%d\t%s\t%s\n",
                results[i].ip, results[i].port, results[i].status,
                results[i].latency_ms, results[i].banner, results[i].tcp_window_size,
                results[i].response_time_ms, results[i].response_pattern,
                results[i].detected_service, results[i].detected_version,
                results[i].confidence_level, results[i].iot_vendor, results[i].iot_device_model);
    }
    fclose(file);
}

void export_csv(ScanResult *results, int count, const char *filename) {
    char full_path[256];
    snprintf(full_path, sizeof(full_path), "./out/%s", filename);
    FILE *file = fopen(full_path, "a");
    if (!file) return;

    // Check if file is empty (new file) and add header
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    if (file_size == 0) {
        fprintf(file, "ip,port,status,latency_ms,banner,tcp_window_size,response_time_ms,response_pattern,detected_service,detected_version,confidence_level,iot_vendor,iot_device_model\n");
    }

    for (int i = 0; i < count; i++) {
        fprintf(file, "%s,%d,%s,%ld,\"%s\",%d,%ld,\"%s\",\"%s\",\"%s\",%d,\"%s\",\"%s\"\n",
                results[i].ip, results[i].port, results[i].status,
                results[i].latency_ms, results[i].banner, results[i].tcp_window_size,
                results[i].response_time_ms, results[i].response_pattern,
                results[i].detected_service, results[i].detected_version,
                results[i].confidence_level, results[i].iot_vendor, results[i].iot_device_model);
    }
    fclose(file);
}

void export_json(ScanResult *results, int count, const char *filename) {
    char full_path[256];
    snprintf(full_path, sizeof(full_path), "./out/%s", filename);
    FILE *file = fopen(full_path, "a");
    if (!file) return;

    // Use JSON Lines format for append compatibility
    for (int i = 0; i < count; i++) {
        fprintf(file, "{\"ip\": \"%s\", \"port\": %d, \"status\": \"%s\", \"latency_ms\": %ld, \"banner\": \"%s\", \"tcp_window_size\": %d, \"response_time_ms\": %ld, \"response_pattern\": \"%s\", \"detected_service\": \"%s\", \"detected_version\": \"%s\", \"confidence_level\": %d, \"iot_vendor\": \"%s\", \"iot_device_model\": \"%s\"}\n",
                results[i].ip, results[i].port, results[i].status,
                results[i].latency_ms, results[i].banner, results[i].tcp_window_size,
                results[i].response_time_ms, results[i].response_pattern,
                results[i].detected_service, results[i].detected_version,
                results[i].confidence_level, results[i].iot_vendor, results[i].iot_device_model);
    }
    fclose(file);
}