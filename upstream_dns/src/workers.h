#ifndef WORKERS_H
#define WORKERS_H

#include <stdint.h>
#include <sys/types.h>      /* ssize_t */
#include <sys/socket.h>     /* sockaddr_storage, socklen_t */
#include <netinet/in.h>     /* INET6_ADDRSTRLEN */

#include "types.h"          /* MAXLINE */

/* UDP query processing context (IPv4 or IPv6).
 * buffer is embedded directly (no separate malloc/free per query). */
struct QueryContext {
    int dns_sock;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    char buffer[MAXLINE];
    ssize_t recv_len;
    unsigned long query_num;
};

/* TCP query processing context. */
struct TCPQueryContext {
    int client_fd;
    char client_ip[INET6_ADDRSTRLEN];
    uint16_t client_port;
};

/* Thread-pool task entry points dispatched by main()'s accept loops. */
void* process_query(void* arg);
void* process_tcp_query(void* arg);

#endif /* WORKERS_H */
