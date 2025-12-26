#include "syn_scan.h"
#include "banner.h"
#include "service_detect.h"
#include "scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>

// Pseudo header for TCP checksum calculation
struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

unsigned short checksum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    for (sum = 0; nwords > 0; nwords--) {
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int create_raw_socket() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Failed to create raw socket");
        return -1;
    }

    // Set IP_HDRINCL to tell kernel we will provide IP header
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Failed to set IP_HDRINCL");
        close(sock);
        return -1;
    }

    return sock;
}

int send_syn_packet(int sock, struct sockaddr_in *target, int port, unsigned int seq_num) {
    char packet[4096];
    memset(packet, 0, 4096);

    // IP header
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Get local IP address
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    getsockname(sock, (struct sockaddr *)&local_addr, &addr_len);

    // Fill IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = local_addr.sin_addr.s_addr;
    iph->daddr = target->sin_addr.s_addr;

    // Fill TCP header
    tcph->source = htons(rand() % 65535);  // Random source port
    tcph->dest = htons(port);
    tcph->seq = htonl(seq_num);
    tcph->ack_seq = 0;
    tcph->doff = 5;  // TCP header size
    tcph->syn = 1;   // SYN flag
    tcph->ack = 0;
    tcph->psh = 0;
    tcph->rst = 0;
    tcph->fin = 0;
    tcph->urg = 0;
    tcph->window = htons(64240);  // Standard window size
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // Calculate TCP checksum
    struct pseudo_header psh;
    psh.source_address = local_addr.sin_addr.s_addr;
    psh.dest_address = target->sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char pseudogram[psize];
    memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    tcph->check = checksum((unsigned short*)pseudogram, psize / 2);

    // Calculate IP checksum
    iph->check = checksum((unsigned short*)packet, iph->tot_len / 2);

    // Send packet
    if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        return -1;
    }

    return 0;
}

void *syn_scanner_thread(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    int raw_sock;
    struct sockaddr_in server_addr;
    struct timespec start, end;
    fd_set readfds;
    struct timeval timeout = {0, 100000}; // 100ms timeout for select

    srand(time(NULL) ^ pthread_self());

    // Create raw socket for this thread
    raw_sock = create_raw_socket();
    if (raw_sock < 0) {
        // If raw socket fails (no root privileges), show warning only once globally
        static int warned = 0;
        if (__sync_bool_compare_and_swap(&warned, 0, 1)) {
            fprintf(stderr, "\n[!] SYN scanning requires root privileges for raw sockets.\n");
            fprintf(stderr, "[!] Try: sudo ./netscope -ss\n");
            fprintf(stderr, "[!] Falling back to connect scan mode...\n\n");
        }

        // Fall back to regular connect scanning
        scanner_thread(arg);
        return NULL;
    }

    // Set non-blocking mode for raw socket
    fcntl(raw_sock, F_SETFL, O_NONBLOCK);

    while (running) {
        // Generate random IP
        unsigned char ip[4];
        ip[0] = rand() % 256;
        ip[1] = rand() % 256;
        ip[2] = rand() % 256;
        ip[3] = rand() % 256;

        // Skip private IP ranges
        if ((ip[0] == 10) ||
            (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
            (ip[0] == 192 && ip[1] == 168) ||
            (ip[0] == 127) ||
            (ip[0] == 0)) {
            continue;
        }

        char ip_str[16];
        sprintf(ip_str, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

        // Setup target address
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr(ip_str);

        // Scan each port
        for (int p = 0; p < data->port_count; p++) {
            int current_port = data->ports[p];
            server_addr.sin_port = htons(current_port);

            // Send SYN packet
            clock_gettime(CLOCK_MONOTONIC, &start);
            unsigned int seq_num = rand();
            if (send_syn_packet(raw_sock, &server_addr, current_port, seq_num) < 0) {
                continue;
            }

            // Wait for response with timeout
            FD_ZERO(&readfds);
            FD_SET(raw_sock, &readfds);

            int activity = select(raw_sock + 1, &readfds, NULL, NULL, &timeout);
            if (activity > 0 && FD_ISSET(raw_sock, &readfds)) {
                // Read response packet
                char response[4096];
                struct sockaddr_in from_addr;
                socklen_t from_len = sizeof(from_addr);

                int bytes_read = recvfrom(raw_sock, response, sizeof(response), 0,
                                        (struct sockaddr *)&from_addr, &from_len);

                if (bytes_read > 0) {
                    struct iphdr *iph = (struct iphdr *)response;
                    struct tcphdr *tcph = (struct tcphdr *)(response + (iph->ihl * 4));

                    // Check if response is from our target and port
                    if (iph->saddr == server_addr.sin_addr.s_addr &&
                        ntohs(tcph->source) == current_port) {

                        clock_gettime(CLOCK_MONOTONIC, &end);
                        long latency_ms = (end.tv_sec - start.tv_sec) * 1000 +
                                        (end.tv_nsec - start.tv_nsec) / 1000000;

                        // Determine port state
                        char status[16];
                        int is_open = 0;

                        if (tcph->syn && tcph->ack) {
                            // SYN-ACK received - port is open
                            strcpy(status, "open");
                            is_open = 1;
                        } else if (tcph->rst) {
                            // RST received - port is closed
                            strcpy(status, "closed");
                        } else {
                            // No expected response
                            strcpy(status, "filtered");
                        }

                        if (is_open) {
                            // Try to get banner using regular connection
                            int banner_sock = socket(AF_INET, SOCK_STREAM, 0);
                            if (banner_sock >= 0) {
                                struct timeval banner_timeout = {TIMEOUT_SEC, TIMEOUT_USEC};
                                setsockopt(banner_sock, SOL_SOCKET, SO_RCVTIMEO, &banner_timeout, sizeof(banner_timeout));
                                setsockopt(banner_sock, SOL_SOCKET, SO_SNDTIMEO, &banner_timeout, sizeof(banner_timeout));

                                if (connect(banner_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
                                    // Get TCP window size
                                    int tcp_window_size = 0;
                                    socklen_t optlen = sizeof(tcp_window_size);
                                    getsockopt(banner_sock, SOL_SOCKET, SO_RCVBUF, &tcp_window_size, &optlen);

                                    // Get banner
                                    char banner[256] = {0};
                                    struct timespec banner_start, banner_end;
                                    clock_gettime(CLOCK_MONOTONIC, &banner_start);

                                    get_banner(banner_sock, banner, sizeof(banner), current_port);

                                    clock_gettime(CLOCK_MONOTONIC, &banner_end);
                                    long response_time_ms = (banner_end.tv_sec - banner_start.tv_sec) * 1000 +
                                                          (banner_end.tv_nsec - banner_start.tv_nsec) / 1000000;

                                    // Store result with service detection
                                    pthread_mutex_lock(&results_mutex);
                                    if (result_count < MAX_RESULTS) {
                                        strcpy(results[result_count].ip, ip_str);
                                        results[result_count].port = current_port;
                                        strcpy(results[result_count].status, status);
                                        results[result_count].latency_ms = latency_ms;
                                        strcpy(results[result_count].banner, banner);
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
                                }
                                close(banner_sock);
                            }
                        }
                    }
                }
            }
        }
    }

    close(raw_sock);
    return NULL;
}
