#ifndef SYN_SCAN_H
#define SYN_SCAN_H

#include "common.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>

// TCP SYN scanning functions
void *syn_scanner_thread(void *arg);
int send_syn_packet(int sock, struct sockaddr_in *target, int port, unsigned int seq_num);
int create_raw_socket();
unsigned short checksum(unsigned short *buf, int nwords);

#endif // SYN_SCAN_H
