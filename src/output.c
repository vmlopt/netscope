#include "output.h"
#include <stdio.h>
#include <string.h>

void export_txt(ScanResult *results, int count, const char *filename) {
    char full_path[256];
    snprintf(full_path, sizeof(full_path), "./out/%s", filename);
    FILE *file = fopen(full_path, "w");
    if (!file) return;

    fprintf(file, "IP Address\tPort\tStatus\tLatency (ms)\tBanner\n");
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
    FILE *file = fopen(full_path, "w");
    if (!file) return;

    fprintf(file, "ip,port,status,latency_ms,banner\n");
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
    FILE *file = fopen(full_path, "w");
    if (!file) return;

    fprintf(file, "[\n");
    for (int i = 0; i < count; i++) {
        fprintf(file, "  {\"ip\": \"%s\", \"port\": %d, \"status\": \"%s\", \"latency_ms\": %ld, \"banner\": \"%s\"}",
                results[i].ip, results[i].port, results[i].status,
                results[i].latency_ms, results[i].banner);
        if (i < count - 1) {
            fprintf(file, ",");
        }
        fprintf(file, "\n");
    }
    fprintf(file, "]\n");
    fclose(file);
}
