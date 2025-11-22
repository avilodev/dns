#include "response.h"


/**
 * Send DNS response to client
 */
int send_response(int sock, struct Packet* response, struct sockaddr_in* client_addr) {
    if (!response || !response->request || !client_addr) {
        fprintf(stderr, "Error: Invalid parameters for send_response\n");
        return -1;
    }

    ssize_t sent = sendto(sock, response->request, response->recv_len, 0,
                          (struct sockaddr*)client_addr, sizeof(*client_addr));
    
    if (sent < 0) {
        perror("Error: Failed to send response to client");
        return -1;
    }

    if (sent != response->recv_len) {
        fprintf(stderr, "Warning: Partial send to client (%zd/%zd bytes)\n",
                sent, response->recv_len);
        return -1;
    }

    return 0;
}

/**
 * Build NXDOMAIN response (domain does not exist)
 */
struct Packet* build_nxdomain_response(struct Packet* request) {
    if (!request) {
        return NULL;
    }

    struct Packet* response = calloc(1, sizeof(struct Packet));
    if (!response) {
        perror("Error: Failed to allocate response packet");
        return NULL;
    }

    response->request = calloc(1, MAXLINE);
    if (!response->request) {
        perror("Error: Failed to allocate response buffer");
        free(response);
        return NULL;
    }

    int pos = 0;

    // Copy transaction ID from request
    memcpy(response->request + pos, request->request, 2);
    pos += 2;

    // Set response flags with NXDOMAIN (rcode=3)
    uint16_t flags = 0;
    flags |= (1 << 15);           // QR: Response
    flags |= (1 << 10);           // AA: Authoritative Answer
    flags |= (request->rd << 8);  // RD: Copy recursion desired
    flags |= (1 << 7);            // RA: Recursion Available
    flags |= RCODE_NAME_ERROR;    // RCODE: Name Error (NXDOMAIN = 3)
    *(uint16_t*)(response->request + pos) = htons(flags);
    pos += 2;

    // Set counts (question only, no answers)
    *(uint16_t*)(response->request + pos) = htons(1);  // QDCOUNT: 1 question
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);  // ANCOUNT: 0 answers
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);  // NSCOUNT: 0
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);  // ARCOUNT: 0
    pos += 2;

    // Copy question section
    if (request->domain) {
        uint8_t domain_len = strlen(request->domain);
        response->request[pos++] = domain_len;
        memcpy(response->request + pos, request->domain, domain_len);
        pos += domain_len;
    }

    if (request->top_level_domain) {
        uint8_t tld_len = strlen(request->top_level_domain);
        response->request[pos++] = tld_len;
        memcpy(response->request + pos, request->top_level_domain, tld_len);
        pos += tld_len;
    }

    response->request[pos++] = 0;  // Null terminator

    *(uint16_t*)(response->request + pos) = htons(request->q_type);
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(request->q_class);
    pos += 2;

    response->recv_len = pos;
    return response;
}