#define _GNU_SOURCE
#include <signal.h>
#include <unistd.h>
#include "signal.h"
#include "common.h"
#include <stdio.h>

void signal_handler(int signum) {
    (void)signum;
    running = 0;
    printf("\nStopping scanner...\n");
}

// Forward declaration to avoid implicit function warning
typedef void (*sighandler_t)(int);
sighandler_t signal(int signum, sighandler_t handler);

void setup_signal_handler() {
    const int SIGINT = 2;  // SIGINT is usually 2
    signal(SIGINT, signal_handler);
}
