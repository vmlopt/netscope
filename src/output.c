#include "output.h"
#include <stdio.h>
#include <string.h>

void export_txt(ScanResult *results, int count, const char *filename) {
    char full_path[256];
    snprintf(full_path, sizeof(full_path), "./out/%s", filename);
    FILE *file = fopen(full_path, "a");
    if (!file) return;

    for (int i = 0; i < count; i++) {
        fprintf(file, "%s\t%d\t%s\t%ld\t%s\n",
                results[i].ip, results[i].port, results[i].status,
                results[i].latency_ms, results[i].banner);
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
        fprintf(file, "ip,port,status,latency_ms,banner\n");
    }

    for (int i = 0; i < count; i++) {
        fprintf(file, "%s,%d,%s,%ld,\"%s\"\n",
                results[i].ip, results[i].port, results[i].status,
                results[i].latency_ms, results[i].banner);
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
        fprintf(file, "{\"ip\": \"%s\", \"port\": %d, \"status\": \"%s\", \"latency_ms\": %ld, \"banner\": \"%s\"}\n",
                results[i].ip, results[i].port, results[i].status,
                results[i].latency_ms, results[i].banner);
    }
    fclose(file);
}