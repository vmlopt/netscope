#include "iot_scan.h"
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
#include <fcntl.h>

// IoT device fingerprints database
#define MAX_IOT_FINGERPRINTS 50
IoTDeviceFingerprint iot_fingerprints[MAX_IOT_FINGERPRINTS];
int iot_fingerprint_count = 0;

// IoT ports to scan (most common ports used by IoT devices)
static const int IOT_PORTS[] = {
    23,   // Telnet
    80,   // HTTP
    443,  // HTTPS
    554,  // RTSP (IP cameras)
    8080, // HTTP Alternative
    8443, // HTTPS Alternative
    2323, // Telnet Alternative
    3721, // Some DVR systems
    34567, // Some IP cameras
    37777, // Some DVR/NVR systems
    10000, // Some webcams
    34599, // Some IP cameras
    1900, // UPnP
    5000, // UPnP Alternative
    21,   // FTP (some cameras)
    990,  // FTPS
    8000, // HTTP Alternative
    9000, // Some DVR systems
    10001, // Some cameras
    34567, // Hikvision cameras
    37777, // Dahua devices
    88,   // Kerberos (some smart devices)
    135,  // RPC (Windows-based IoT)
    139,  // NetBIOS (some smart TVs)
    445,  // SMB (some NAS devices)
    3389, // RDP (some smart displays)
    5900, // VNC (some smart devices)
    62078, // iPhone sync (some IoT)
    62078, // Apple devices
};
#define IOT_PORT_COUNT (sizeof(IOT_PORTS) / sizeof(IOT_PORTS[0]))

unsigned short iot_checksum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    for (sum = 0; nwords > 0; nwords--) {
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int send_iot_syn_packet(int sock, struct sockaddr_in *target, int port) {
    char packet[4096];
    memset(packet, 0, 4096);

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
    tcph->source = htons(12345 + rand() % 10000); // Random high port
    tcph->dest = htons(port);
    tcph->seq = htonl(rand());
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->ack = 0;
    tcph->psh = 0;
    tcph->rst = 0;
    tcph->fin = 0;
    tcph->urg = 0;
    tcph->window = htons(8192); // Smaller window for IoT devices
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // TCP checksum calculation
    struct {
        unsigned int source_address;
        unsigned int dest_address;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
        struct tcphdr tcp;
    } pseudo_header;

    pseudo_header.source_address = local_addr.sin_addr.s_addr;
    pseudo_header.dest_address = target->sin_addr.s_addr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(sizeof(struct tcphdr));
    memcpy(&pseudo_header.tcp, tcph, sizeof(struct tcphdr));

    tcph->check = iot_checksum((unsigned short *)&pseudo_header, sizeof(pseudo_header) / 2);

    // IP checksum
    iph->check = iot_checksum((unsigned short *)packet, iph->tot_len / 2);

    // Send packet (fire and forget - don't wait for response)
    return sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)target, sizeof(*target));
}

void init_iot_fingerprints() {
    // IP Cameras
    strcpy(iot_fingerprints[iot_fingerprint_count].vendor, "Hikvision");
    iot_fingerprints[iot_fingerprint_count].device_type = IOT_CAMERA;
    strcpy(iot_fingerprints[iot_fingerprint_count].model_pattern, "DS-");
    iot_fingerprints[iot_fingerprint_count].default_ports[0] = 80;
    iot_fingerprints[iot_fingerprint_count].default_ports[1] = 554;
    iot_fingerprints[iot_fingerprint_count].default_ports[2] = 8000;
    iot_fingerprints[iot_fingerprint_count].port_count = 3;
    strcpy(iot_fingerprints[iot_fingerprint_count].banner_pattern, "Hikvision");
    strcpy(iot_fingerprints[iot_fingerprint_count].response_pattern, "HTTP/1.1");
    iot_fingerprint_count++;

    strcpy(iot_fingerprints[iot_fingerprint_count].vendor, "Dahua");
    iot_fingerprints[iot_fingerprint_count].device_type = IOT_CAMERA;
    strcpy(iot_fingerprints[iot_fingerprint_count].model_pattern, "IPC-");
    iot_fingerprints[iot_fingerprint_count].default_ports[0] = 80;
    iot_fingerprints[iot_fingerprint_count].default_ports[1] = 37777;
    iot_fingerprints[iot_fingerprint_count].port_count = 2;
    strcpy(iot_fingerprints[iot_fingerprint_count].banner_pattern, "Dahua");
    strcpy(iot_fingerprints[iot_fingerprint_count].response_pattern, "HTTP/1.0");
    iot_fingerprint_count++;

    strcpy(iot_fingerprints[iot_fingerprint_count].vendor, "Foscam");
    iot_fingerprints[iot_fingerprint_count].device_type = IOT_CAMERA;
    strcpy(iot_fingerprints[iot_fingerprint_count].model_pattern, "FI98");
    iot_fingerprints[iot_fingerprint_count].default_ports[0] = 88;
    iot_fingerprints[iot_fingerprint_count].default_ports[1] = 80;
    iot_fingerprints[iot_fingerprint_count].port_count = 2;
    strcpy(iot_fingerprints[iot_fingerprint_count].banner_pattern, "Foscam");
    strcpy(iot_fingerprints[iot_fingerprint_count].response_pattern, "");
    iot_fingerprint_count++;

    // DVR/NVR Systems
    strcpy(iot_fingerprints[iot_fingerprint_count].vendor, "Hikvision");
    iot_fingerprints[iot_fingerprint_count].device_type = IOT_DVR;
    strcpy(iot_fingerprints[iot_fingerprint_count].model_pattern, "iDS-");
    iot_fingerprints[iot_fingerprint_count].default_ports[0] = 80;
    iot_fingerprints[iot_fingerprint_count].default_ports[1] = 554;
    iot_fingerprints[iot_fingerprint_count].default_ports[2] = 8000;
    iot_fingerprints[iot_fingerprint_count].port_count = 3;
    strcpy(iot_fingerprints[iot_fingerprint_count].banner_pattern, "Hikvision");
    strcpy(iot_fingerprints[iot_fingerprint_count].response_pattern, "DVR");
    iot_fingerprint_count++;

    strcpy(iot_fingerprints[iot_fingerprint_count].vendor, "Dahua");
    iot_fingerprints[iot_fingerprint_count].device_type = IOT_NVR;
    strcpy(iot_fingerprints[iot_fingerprint_count].model_pattern, "NVR");
    iot_fingerprints[iot_fingerprint_count].default_ports[0] = 80;
    iot_fingerprints[iot_fingerprint_count].default_ports[1] = 37777;
    iot_fingerprints[iot_fingerprint_count].port_count = 2;
    strcpy(iot_fingerprints[iot_fingerprint_count].banner_pattern, "Dahua");
    strcpy(iot_fingerprints[iot_fingerprint_count].response_pattern, "NVR");
    iot_fingerprint_count++;

    // Routers
    strcpy(iot_fingerprints[iot_fingerprint_count].vendor, "TP-Link");
    iot_fingerprints[iot_fingerprint_count].device_type = IOT_ROUTER;
    strcpy(iot_fingerprints[iot_fingerprint_count].model_pattern, "TL-");
    iot_fingerprints[iot_fingerprint_count].default_ports[0] = 80;
    iot_fingerprints[iot_fingerprint_count].default_ports[1] = 8080;
    iot_fingerprints[iot_fingerprint_count].port_count = 2;
    strcpy(iot_fingerprints[iot_fingerprint_count].banner_pattern, "TP-Link");
    strcpy(iot_fingerprints[iot_fingerprint_count].response_pattern, "Router");
    iot_fingerprint_count++;

    strcpy(iot_fingerprints[iot_fingerprint_count].vendor, "D-Link");
    iot_fingerprints[iot_fingerprint_count].device_type = IOT_ROUTER;
    strcpy(iot_fingerprints[iot_fingerprint_count].model_pattern, "DIR-");
    iot_fingerprints[iot_fingerprint_count].default_ports[0] = 80;
    iot_fingerprints[iot_fingerprint_count].port_count = 1;
    strcpy(iot_fingerprints[iot_fingerprint_count].banner_pattern, "D-Link");
    strcpy(iot_fingerprints[iot_fingerprint_count].response_pattern, "Router");
    iot_fingerprint_count++;

    // Smart TVs
    strcpy(iot_fingerprints[iot_fingerprint_count].vendor, "Samsung");
    iot_fingerprints[iot_fingerprint_count].device_type = IOT_SMART_TV;
    strcpy(iot_fingerprints[iot_fingerprint_count].model_pattern, "Samsung");
    iot_fingerprints[iot_fingerprint_count].default_ports[0] = 80;
    iot_fingerprints[iot_fingerprint_count].default_ports[1] = 8001;
    iot_fingerprints[iot_fingerprint_count].port_count = 2;
    strcpy(iot_fingerprints[iot_fingerprint_count].banner_pattern, "Samsung");
    strcpy(iot_fingerprints[iot_fingerprint_count].response_pattern, "TV");
    iot_fingerprint_count++;

    strcpy(iot_fingerprints[iot_fingerprint_count].vendor, "LG");
    iot_fingerprints[iot_fingerprint_count].device_type = IOT_SMART_TV;
    strcpy(iot_fingerprints[iot_fingerprint_count].model_pattern, "LG");
    iot_fingerprints[iot_fingerprint_count].default_ports[0] = 80;
    iot_fingerprints[iot_fingerprint_count].port_count = 1;
    strcpy(iot_fingerprints[iot_fingerprint_count].banner_pattern, "LG");
    strcpy(iot_fingerprints[iot_fingerprint_count].response_pattern, "TV");
    iot_fingerprint_count++;

    // Smart Bulbs/Lights
    strcpy(iot_fingerprints[iot_fingerprint_count].vendor, "Philips");
    iot_fingerprints[iot_fingerprint_count].device_type = IOT_SMART_BULB;
    strcpy(iot_fingerprints[iot_fingerprint_count].model_pattern, "Hue");
    iot_fingerprints[iot_fingerprint_count].default_ports[0] = 80;
    iot_fingerprints[iot_fingerprint_count].default_ports[1] = 443;
    iot_fingerprints[iot_fingerprint_count].port_count = 2;
    strcpy(iot_fingerprints[iot_fingerprint_count].banner_pattern, "Philips Hue");
    strcpy(iot_fingerprints[iot_fingerprint_count].response_pattern, "Light");
    iot_fingerprint_count++;

    // Thermostats
    strcpy(iot_fingerprints[iot_fingerprint_count].vendor, "Nest");
    iot_fingerprints[iot_fingerprint_count].device_type = IOT_THERMOSTAT;
    strcpy(iot_fingerprints[iot_fingerprint_count].model_pattern, "Nest");
    iot_fingerprints[iot_fingerprint_count].default_ports[0] = 80;
    iot_fingerprints[iot_fingerprint_count].default_ports[1] = 443;
    iot_fingerprints[iot_fingerprint_count].port_count = 2;
    strcpy(iot_fingerprints[iot_fingerprint_count].banner_pattern, "Nest");
    strcpy(iot_fingerprints[iot_fingerprint_count].response_pattern, "Thermostat");
    iot_fingerprint_count++;

    // Printers
    strcpy(iot_fingerprints[iot_fingerprint_count].vendor, "HP");
    iot_fingerprints[iot_fingerprint_count].device_type = IOT_PRINTER;
    strcpy(iot_fingerprints[iot_fingerprint_count].model_pattern, "HP ");
    iot_fingerprints[iot_fingerprint_count].default_ports[0] = 80;
    iot_fingerprints[iot_fingerprint_count].default_ports[1] = 443;
    iot_fingerprints[iot_fingerprint_count].default_ports[2] = 631;
    iot_fingerprints[iot_fingerprint_count].port_count = 3;
    strcpy(iot_fingerprints[iot_fingerprint_count].banner_pattern, "HP ");
    strcpy(iot_fingerprints[iot_fingerprint_count].response_pattern, "Printer");
    iot_fingerprint_count++;

    // NAS Devices
    strcpy(iot_fingerprints[iot_fingerprint_count].vendor, "Synology");
    iot_fingerprints[iot_fingerprint_count].device_type = IOT_NAS;
    strcpy(iot_fingerprints[iot_fingerprint_count].model_pattern, "DS");
    iot_fingerprints[iot_fingerprint_count].default_ports[0] = 80;
    iot_fingerprints[iot_fingerprint_count].default_ports[1] = 443;
    iot_fingerprints[iot_fingerprint_count].default_ports[2] = 5000;
    iot_fingerprints[iot_fingerprint_count].port_count = 3;
    strcpy(iot_fingerprints[iot_fingerprint_count].banner_pattern, "Synology");
    strcpy(iot_fingerprints[iot_fingerprint_count].response_pattern, "NAS");
    iot_fingerprint_count++;

    strcpy(iot_fingerprints[iot_fingerprint_count].vendor, "QNAP");
    iot_fingerprints[iot_fingerprint_count].device_type = IOT_NAS;
    strcpy(iot_fingerprints[iot_fingerprint_count].model_pattern, "TS");
    iot_fingerprints[iot_fingerprint_count].default_ports[0] = 80;
    iot_fingerprints[iot_fingerprint_count].default_ports[1] = 443;
    iot_fingerprints[iot_fingerprint_count].port_count = 2;
    strcpy(iot_fingerprints[iot_fingerprint_count].banner_pattern, "QNAP");
    strcpy(iot_fingerprints[iot_fingerprint_count].response_pattern, "NAS");
    iot_fingerprint_count++;
}

IoTDeviceType identify_iot_device(const char *banner, int port) {
    if (!banner || !banner[0]) {
        return IOT_UNKNOWN;
    }

    // Initialize fingerprints if not already done
    static int initialized = 0;
    if (!initialized) {
        init_iot_fingerprints();
        initialized = 1;
    }

    for (int i = 0; i < iot_fingerprint_count; i++) {
        if (strstr(banner, iot_fingerprints[i].banner_pattern) != NULL ||
            strstr(banner, iot_fingerprints[i].vendor) != NULL) {
            return iot_fingerprints[i].device_type;
        }
    }

    // Port-based identification for common IoT ports
    switch (port) {
        case 23:
        case 2323:
            return IOT_ROUTER; // Often routers with telnet
        case 554:
            return IOT_CAMERA; // RTSP port for cameras
        case 1900:
            return IOT_WEB_SERVER; // UPnP port
        case 37777:
            return IOT_DVR; // Dahua DVR port
        case 34567:
            return IOT_CAMERA; // Hikvision camera port
        default:
            return IOT_UNKNOWN;
    }
}

void detect_iot_device(ScanResult *result) {
    result->iot_device_type = identify_iot_device(result->banner, result->port);

    // Set device type name and vendor based on detection
    switch (result->iot_device_type) {
        case IOT_CAMERA:
            strcpy(result->iot_vendor, "IP Camera");
            strcpy(result->iot_device_model, "Network Camera");
            break;
        case IOT_ROUTER:
            strcpy(result->iot_vendor, "Router");
            strcpy(result->iot_device_model, "Network Router");
            break;
        case IOT_DVR:
            strcpy(result->iot_vendor, "DVR");
            strcpy(result->iot_device_model, "Digital Video Recorder");
            break;
        case IOT_NVR:
            strcpy(result->iot_vendor, "NVR");
            strcpy(result->iot_device_model, "Network Video Recorder");
            break;
        case IOT_SMART_TV:
            strcpy(result->iot_vendor, "Smart TV");
            strcpy(result->iot_device_model, "Smart Television");
            break;
        case IOT_SMART_BULB:
            strcpy(result->iot_vendor, "Smart Light");
            strcpy(result->iot_device_model, "Smart Bulb/Light");
            break;
        case IOT_THERMOSTAT:
            strcpy(result->iot_vendor, "Thermostat");
            strcpy(result->iot_device_model, "Smart Thermostat");
            break;
        case IOT_DOORBELL:
            strcpy(result->iot_vendor, "Doorbell");
            strcpy(result->iot_device_model, "Smart Doorbell");
            break;
        case IOT_PRINTER:
            strcpy(result->iot_vendor, "Printer");
            strcpy(result->iot_device_model, "Network Printer");
            break;
        case IOT_NAS:
            strcpy(result->iot_vendor, "NAS");
            strcpy(result->iot_device_model, "Network Attached Storage");
            break;
        case IOT_IP_PHONE:
            strcpy(result->iot_vendor, "IP Phone");
            strcpy(result->iot_device_model, "VoIP Phone");
            break;
        case IOT_WEB_SERVER:
            strcpy(result->iot_vendor, "Web Server");
            strcpy(result->iot_device_model, "Embedded Web Server");
            break;
        default:
            strcpy(result->iot_vendor, "Unknown");
            strcpy(result->iot_device_model, "IoT Device");
            break;
    }
}

void *iot_scanner_thread(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    int raw_sock;

    srand(time(NULL) ^ pthread_self());

    // Create raw socket for IoT scanning
    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock < 0) {
        // If raw socket fails (no root privileges), show warning only once globally
        static int warned = 0;
        if (__sync_bool_compare_and_swap(&warned, 0, 1)) {
            fprintf(stderr, "\n[!] IoT scanning requires root privileges for raw sockets.\n");
            fprintf(stderr, "[!] Try: sudo ./netscope -iot\n");
            fprintf(stderr, "[!] Falling back to connect scan mode...\n\n");
        }

        // Fall back to regular connect scanning
        scanner_thread(arg);
        return NULL;
    }

    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Failed to set IP_HDRINCL for IoT scan");
        close(raw_sock);
        return NULL;
    }

    while (running) {
        // Generate random IP
        unsigned char ip[4];
        ip[0] = rand() % 256;
        ip[1] = rand() % 256;
        ip[2] = rand() % 256;
        ip[3] = rand() % 256;

        // Skip private IP ranges (focus on public IoT devices)
        if ((ip[0] == 10) ||
            (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
            (ip[0] == 192 && ip[1] == 168) ||
            (ip[0] == 127) ||
            (ip[0] == 0)) {
            continue;
        }

        char ip_str[16];
        sprintf(ip_str, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr(ip_str);

        // Scan IoT ports (fire and forget approach)
        for (int i = 0; i < IOT_PORT_COUNT; i++) {
            int port = IOT_PORTS[i];
            server_addr.sin_port = htons(port);

            // Send SYN packet (no response waiting)
            send_iot_syn_packet(raw_sock, &server_addr, port);

            // Small delay to avoid overwhelming network
            usleep(1000); // 1ms delay
        }

        // For each potential IoT device, try to connect and identify
        // This is a simplified approach - in practice, you'd want to
        // capture responses and identify devices that actually respond
        for (int i = 0; i < IOT_PORT_COUNT && i < 5; i++) { // Limit to first 5 ports for efficiency
            int port = IOT_PORTS[i];

            // Try to connect and get banner (similar to regular scanning)
            int banner_sock = socket(AF_INET, SOCK_STREAM, 0);
            if (banner_sock >= 0) {
                struct sockaddr_in banner_addr = server_addr;
                banner_addr.sin_port = htons(port);

                struct timeval timeout = {0, 500000}; // 500ms timeout for IoT devices
                setsockopt(banner_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                setsockopt(banner_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

                if (connect(banner_sock, (struct sockaddr *)&banner_addr, sizeof(banner_addr)) == 0) {
                    // Get TCP info
                    int tcp_window_size = 0;
                    socklen_t optlen = sizeof(tcp_window_size);
                    getsockopt(banner_sock, SOL_SOCKET, SO_RCVBUF, &tcp_window_size, &optlen);

                    // Get banner
                    char banner[256] = {0};
                    struct timespec banner_start, banner_end;
                    clock_gettime(CLOCK_MONOTONIC, &banner_start);

                    get_banner(banner_sock, banner, sizeof(banner), port);

                    clock_gettime(CLOCK_MONOTONIC, &banner_end);
                    long response_time_ms = (banner_end.tv_sec - banner_start.tv_sec) * 1000 +
                                          (banner_end.tv_nsec - banner_start.tv_nsec) / 1000000;

                    // Store IoT device result
                    pthread_mutex_lock(&results_mutex);
                    if (result_count < MAX_RESULTS) {
                        strcpy(results[result_count].ip, ip_str);
                        results[result_count].port = port;
                        strcpy(results[result_count].status, "open");
                        results[result_count].latency_ms = response_time_ms;
                        strcpy(results[result_count].banner, banner);
                        results[result_count].tcp_window_size = tcp_window_size;
                        results[result_count].response_time_ms = response_time_ms;

                        // Perform service detection
                        detect_service(&results[result_count]);

                        // Perform IoT device detection
                        detect_iot_device(&results[result_count]);

                        result_count++;

                        printf("IoT Found: %s:%d (%ldms) [%s - %s]",
                               ip_str, port, response_time_ms,
                               results[result_count-1].iot_vendor,
                               results[result_count-1].iot_device_model);

                        if (strcmp(results[result_count-1].detected_service, "Unknown") != 0) {
                            printf(" [%s %s %d%%]",
                                   results[result_count-1].detected_service,
                                   results[result_count-1].detected_version,
                                   results[result_count-1].confidence_level);
                        }

                        if (banner[0]) {
                            printf(" - %s", banner);
                        }
                        printf("\n");
                    }
                    pthread_mutex_unlock(&results_mutex);
                }
                close(banner_sock);
            }
        }

        // Longer delay between IP scans for IoT devices
        usleep(10000); // 10ms delay between IPs
    }

    close(raw_sock);
    return NULL;
}
