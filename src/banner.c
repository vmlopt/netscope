#include "banner.h"
#include <string.h>
#include <unistd.h>

void get_banner(int sock, char *banner, size_t banner_size, int port) {
    if (port == 80 || port == 443) {
        // HTTP banner detection
        const char *http_request = "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n";
        char response[1024] = {0};

        send(sock, http_request, strlen(http_request), 0);

        int bytes_read = recv(sock, response, sizeof(response) - 1, 0);
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
    }

    // Default empty banner
    banner[0] = '\0';
}
