#include "scanner.h"
#include "banner.h"
#include "service_detect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

void *scanner_thread(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    int sock;
    struct sockaddr_in server_addr;
    struct timeval timeout = {TIMEOUT_SEC, TIMEOUT_USEC};
    struct timespec start, end;

    srand(time(NULL) ^ pthread_self());

    while (running) {
        // สุ่ม IP address
        unsigned char ip[4];
        ip[0] = rand() % 256;
        ip[1] = rand() % 256;
        ip[2] = rand() % 256;
        ip[3] = rand() % 256;

        // ข้าม private IP ranges
        if ((ip[0] == 10) ||
            (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
            (ip[0] == 192 && ip[1] == 168) ||
            (ip[0] == 127) ||
            (ip[0] == 0)) {
            continue;
        }

        char ip_str[16];
        sprintf(ip_str, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

        // วน loop ผ่านทุก port สำหรับ IP นี้
        for (int p = 0; p < data->port_count; p++) {
            int current_port = data->ports[p];

            // สร้าง socket
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;

            // ตั้ง timeout
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

            // ตั้งค่า server address
            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(current_port);
            server_addr.sin_addr.s_addr = inet_addr(ip_str);

            // Start timing
            clock_gettime(CLOCK_MONOTONIC, &start);

            // พยายามเชื่อมต่อ
            if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
                // End timing
                clock_gettime(CLOCK_MONOTONIC, &end);
                long latency_ms = (end.tv_sec - start.tv_sec) * 1000 +
                                 (end.tv_nsec - start.tv_nsec) / 1000000;

                // Get TCP window size
                int tcp_window_size = 0;
                socklen_t optlen = sizeof(tcp_window_size);
                getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &tcp_window_size, &optlen);

                // Get banner with enhanced detection
                char banner[256] = {0};
                struct timespec banner_start, banner_end;
                clock_gettime(CLOCK_MONOTONIC, &banner_start);

                get_banner(sock, banner, sizeof(banner), current_port);

                clock_gettime(CLOCK_MONOTONIC, &banner_end);
                long response_time_ms = (banner_end.tv_sec - banner_start.tv_sec) * 1000 +
                                       (banner_end.tv_nsec - banner_start.tv_nsec) / 1000000;

                // เชื่อมต่อได้! บันทึกผล
                pthread_mutex_lock(&results_mutex);
                if (result_count < MAX_RESULTS) {
                    strcpy(results[result_count].ip, ip_str);
                    results[result_count].port = current_port;
                    strcpy(results[result_count].status, "open");
                    results[result_count].latency_ms = latency_ms;
                    strcpy(results[result_count].banner, banner);

                    // Service detection data
                    results[result_count].tcp_window_size = tcp_window_size;
                    results[result_count].response_time_ms = response_time_ms;

                    // Perform service detection
                    detect_service(&results[result_count]);

                    result_count++;

                    printf("Found: %s:%d (%ldms", ip_str, current_port, latency_ms);
                    if (banner[0]) printf(", %s", banner);
                    if (strcmp(results[result_count-1].detected_service, "Unknown") != 0) {
                        printf(" [%s %s %d%%]", results[result_count-1].detected_service,
                               results[result_count-1].detected_version,
                               results[result_count-1].confidence_level);
                    }
                    printf(")\n");
                }
                pthread_mutex_unlock(&results_mutex);

                // บันทึกแบบเดิมด้วย (สำหรับ backward compatibility)
                pthread_mutex_lock(data->file_mutex);
                fprintf(data->output_file, "%s:%d\n", ip_str, current_port);
                fflush(data->output_file);
                pthread_mutex_unlock(data->file_mutex);
            }

            close(sock);
        }
    }

    return NULL;
}
