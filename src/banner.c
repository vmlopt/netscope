#include "banner.h"
#include <string.h>
#include <unistd.h>
#include <stdio.h>

void get_banner(int sock, char *banner, size_t banner_size, int port) {
    char response[1024] = {0};
    int bytes_read = 0;

    switch (port) {
        case 21: // FTP
            // Send FTP greeting probe
            bytes_read = recv(sock, response, sizeof(response) - 1, 0);
            if (bytes_read > 0) {
                response[bytes_read] = '\0';
                // FTP servers usually send a 220 response
                if (strstr(response, "220")) {
                    char *start = strstr(response, "220");
                    if (start) {
                        start += 4; // Skip "220 "
                        char *end = strstr(start, "\r\n");
                        if (end) {
                            size_t len = end - start;
                            if (len < banner_size) {
                                strncpy(banner, start, len);
                                banner[len] = '\0';
                                return;
                            }
                        }
                    }
                }
            }
            break;

        case 22: // SSH
            // SSH banner is usually sent immediately upon connection
            bytes_read = recv(sock, response, sizeof(response) - 1, 0);
            if (bytes_read > 0) {
                response[bytes_read] = '\0';
                // SSH banner starts with "SSH-"
                if (strstr(response, "SSH-")) {
                    char *end = strstr(response, "\r\n");
                    if (end) {
                        size_t len = end - response;
                        if (len < banner_size) {
                            strncpy(banner, response, len);
                            banner[len] = '\0';
                            return;
                        }
                    }
                }
            }
            break;

        case 25: // SMTP
        case 587: // SMTP Submission
            // SMTP greeting
            bytes_read = recv(sock, response, sizeof(response) - 1, 0);
            if (bytes_read > 0) {
                response[bytes_read] = '\0';
                if (strstr(response, "220")) {
                    char *start = strstr(response, "220");
                    if (start) {
                        start += 4; // Skip "220 "
                        char *end = strstr(start, "\r\n");
                        if (end) {
                            size_t len = end - start;
                            if (len < banner_size) {
                                strncpy(banner, start, len);
                                banner[len] = '\0';
                                return;
                            }
                        }
                    }
                }
            }
            break;

        case 53: // DNS (TCP)
            // DNS version.bind query (similar to nmap)
            const char *dns_query = "\x00\x1d\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03";
            send(sock, dns_query, 29, 0);

            bytes_read = recv(sock, response, sizeof(response) - 1, 0);
            if (bytes_read > 12) { // DNS header is 12 bytes
                // Simple check for valid DNS response
                if ((response[2] & 0x80) && (response[3] & 0x80)) { // QR and AA bits set
                    strcpy(banner, "DNS");
                    return;
                }
            }
            break;

        case 80:  // HTTP
        case 443: // HTTPS (though we don't handle SSL here)
        case 8080: // HTTP Alternative
        case 8443: // HTTPS Alternative
            // HTTP banner detection
            const char *http_request = "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n";
            send(sock, http_request, strlen(http_request), 0);

            bytes_read = recv(sock, response, sizeof(response) - 1, 0);
            if (bytes_read > 0) {
                response[bytes_read] = '\0';

                // Extract server header
                char *server_line = strstr(response, "Server: ");
                if (server_line) {
                    server_line += 8; // Skip "Server: "
                    char *end = strstr(server_line, "\r\n");
                    if (end) {
                        size_t len = end - server_line;
                        if (len < banner_size) {
                            strncpy(banner, server_line, len);
                            banner[len] = '\0';
                            return;
                        }
                    }
                }
            }
            break;

        case 110: // POP3
            bytes_read = recv(sock, response, sizeof(response) - 1, 0);
            if (bytes_read > 0) {
                response[bytes_read] = '\0';
                if (strstr(response, "+OK")) {
                    char *start = strstr(response, "+OK");
                    if (start) {
                        start += 4; // Skip "+OK "
                        char *end = strstr(start, "\r\n");
                        if (end) {
                            size_t len = end - start;
                            if (len < banner_size) {
                                strncpy(banner, start, len);
                                banner[len] = '\0';
                                return;
                            }
                        }
                    }
                }
            }
            break;

        case 143: // IMAP
            bytes_read = recv(sock, response, sizeof(response) - 1, 0);
            if (bytes_read > 0) {
                response[bytes_read] = '\0';
                if (strstr(response, "* OK")) {
                    char *start = strstr(response, "* OK");
                    if (start) {
                        start += 5; // Skip "* OK "
                        char *end = strstr(start, "\r\n");
                        if (end) {
                            size_t len = end - start;
                            if (len < banner_size) {
                                strncpy(banner, start, len);
                                banner[len] = '\0';
                                return;
                            }
                        }
                    }
                }
            }
            break;

        case 3306: // MySQL
            // MySQL protocol handshake
            bytes_read = recv(sock, response, sizeof(response) - 1, 0);
            if (bytes_read > 0) {
                // MySQL handshake packet starts with protocol version
                if (bytes_read >= 5 && response[0] >= 10) { // Protocol version >= 10
                    int version_len = response[0];
                    if (version_len < banner_size && version_len < bytes_read) {
                        strncpy(banner, &response[1], version_len);
                        banner[version_len] = '\0';
                        return;
                    }
                }
            }
            break;

        case 5432: // PostgreSQL
            // PostgreSQL protocol startup message
            const char *pg_startup = "\x00\x00\x00\x08\x04\xd2\x16\x2f";
            send(sock, pg_startup, 8, 0);

            bytes_read = recv(sock, response, sizeof(response) - 1, 0);
            if (bytes_read > 0) {
                if (response[0] == 'R') { // Authentication request
                    strcpy(banner, "PostgreSQL");
                    return;
                }
            }
            break;

        default:
            // Generic banner grabbing - try to read any initial response
            bytes_read = recv(sock, response, sizeof(response) - 1, 0);
            if (bytes_read > 0) {
                response[bytes_read] = '\0';
                // Take first line as banner
                char *end = strstr(response, "\r\n");
                if (!end) end = strstr(response, "\n");
                if (end) {
                    size_t len = end - response;
                    if (len < banner_size) {
                        strncpy(banner, response, len);
                        banner[len] = '\0';
                        return;
                    }
                } else if (bytes_read < banner_size) {
                    strcpy(banner, response);
                    return;
                }
            }
            break;
    }

    // Default empty banner
    banner[0] = '\0';
}
