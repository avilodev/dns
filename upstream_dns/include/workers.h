#ifndef WORKERS_H
#define WORKERS_H

#include "types.h"

/* A cache-miss UDP datagram handed to the worker pool. */
struct QueryContext {
    int dns_sock;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    char buffer[MAXLINE];
    ssize_t recv_len;
};

/* An accepted TCP connection (served until EOF or idle timeout). */
struct TCPQueryContext {
    int client_fd;
    struct sockaddr_storage client_ss;
};

/* Thread-pool tasks; both free their context. */
void* process_query(void* arg);
void* process_tcp_query(void* arg);

#endif /* WORKERS_H */
