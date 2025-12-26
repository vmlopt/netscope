#include "args.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void parse_arguments(int argc, char *argv[], int *num_threads) {
    *num_threads = 100;
    scan_type = SCAN_CONNECT;  // Default to connect scan
    // Initialize default port
    ports[0] = DEFAULT_PORT;
    port_count = 1;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) {
            // Parse comma-separated ports
            char *ports_str = argv[i + 1];
            char *token = strtok(ports_str, ",");
            port_count = 0;

            while (token != NULL && port_count < MAX_PORTS) {
                int port = atoi(token);
                if (port > 0 && port <= 65535) {
                    ports[port_count++] = port;
                }
                token = strtok(NULL, ",");
            }

            // If no valid ports, use default
            if (port_count == 0) {
                ports[0] = DEFAULT_PORT;
                port_count = 1;
                printf("No valid ports specified. Using default port %d.\n", DEFAULT_PORT);
            }

            i++; // Skip the next argument
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "txt") == 0) {
                output_format = OUTPUT_TXT;
            } else if (strcmp(argv[i + 1], "json") == 0) {
                output_format = OUTPUT_JSON;
            } else if (strcmp(argv[i + 1], "csv") == 0) {
                output_format = OUTPUT_CSV;
            } else {
                printf("Invalid output format: %s. Using txt.\n", argv[i + 1]);
                output_format = OUTPUT_TXT;
            }
            i++; // Skip the next argument
        } else if (strcmp(argv[i], "-ss") == 0 || strcmp(argv[i], "--syn") == 0) {
            scan_type = SCAN_SYN;
        } else if (strcmp(argv[i], "-iot") == 0) {
            scan_type = SCAN_IOT;
        } else if (atoi(argv[i]) > 0) {
            // First number is threads
            *num_threads = atoi(argv[i]);
            if (*num_threads <= 0 || *num_threads > MAX_THREADS) {
                *num_threads = 100;
            }
        }
    }
}
