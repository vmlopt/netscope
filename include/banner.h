#ifndef BANNER_H
#define BANNER_H

#include "common.h"

// Function to get banner from a connected socket
void get_banner(int sock, char *banner, size_t banner_size, int port);

#endif // BANNER_H
