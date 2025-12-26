#include "common.h"
#include "args.h"
#include "signal.h"
#include "utils.h"
#include "scanner.h"
#include "syn_scan.h"
#include "iot_scan.h"
#include "output.h"
#include <stdio.h>
#include <stdlib.h>

// Define global variables
volatile int running = 1;
ScanResult results[MAX_RESULTS];
int result_count = 0;
OutputFormat output_format = OUTPUT_TXT;
ScanType scan_type = SCAN_CONNECT;
int ports[MAX_PORTS];
int port_count = 1;
pthread_mutex_t results_mutex;

int main(int argc, char *argv[]) {
    int num_threads = 100;

    // Parse arguments
    parse_arguments(argc, argv, &num_threads);

    // Setup signal handling
    setup_signal_handler();

    // Initialize results mutex
    pthread_mutex_init(&results_mutex, NULL);

    printf("IP Scanner - Scanning for open ports: ");
    for (int i = 0; i < port_count; i++) {
        printf("%d", ports[i]);
        if (i < port_count - 1) printf(", ");
    }
    printf("\n");
    printf("Threads: %d\n", num_threads);
    printf("Output format: ");
    switch (output_format) {
        case OUTPUT_TXT: printf("txt\n"); break;
        case OUTPUT_JSON: printf("json\n"); break;
        case OUTPUT_CSV: printf("csv\n"); break;
    }
    printf("Scan type: ");
    switch (scan_type) {
        case SCAN_CONNECT: printf("TCP Connect\n"); break;
        case SCAN_SYN: printf("TCP SYN (-sS)\n"); break;
        case SCAN_IOT: printf("IoT Device Scan (-iot)\n"); break;
    }
    printf("Press Ctrl+C to stop\n\n");

    FILE *output_file = fopen("ip.txt", "a");
    if (!output_file) {
        perror("Cannot open ip.txt");
        return 1;
    }

    pthread_mutex_t file_mutex;
    pthread_mutex_init(&file_mutex, NULL);

    pthread_t threads[MAX_THREADS];
    ThreadData thread_data[MAX_THREADS];

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].ports = ports;
        thread_data[i].port_count = port_count;
        thread_data[i].output_file = output_file;
        thread_data[i].file_mutex = &file_mutex;

        void *(*scan_function)(void *) = (scan_type == SCAN_SYN) ? syn_scanner_thread :
                                         (scan_type == SCAN_IOT) ? iot_scanner_thread : scanner_thread;

        if (pthread_create(&threads[i], NULL, scan_function, &thread_data[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    fclose(output_file);
    pthread_mutex_destroy(&file_mutex);

    // Create output directory and export results in selected format
    create_output_dir();
    char ports_list[256] = {0};
    for (int i = 0; i < port_count; i++) {
        char port_str[16];
        sprintf(port_str, "%d", ports[i]);
        if (i > 0) strcat(ports_list, ",");
        strcat(ports_list, port_str);
    }

    switch (output_format) {
        case OUTPUT_TXT:
            export_txt(results, result_count, "scan_results.txt");
            printf("Scanner stopped. Results saved to ip.txt and ./out/scan_results.txt\n");
            break;
        case OUTPUT_JSON:
            export_json(results, result_count, "scan_results.json");
            printf("Scanner stopped. Results saved to ip.txt and ./out/scan_results.json\n");
            break;
        case OUTPUT_CSV:
            export_csv(results, result_count, "scan_results.csv");
            printf("Scanner stopped. Results saved to ip.txt and ./out/scan_results.csv\n");
            break;
    }

    printf("Total hosts found: %d\n", result_count);

    // Cleanup results mutex
    pthread_mutex_destroy(&results_mutex);

    return 0;
}
