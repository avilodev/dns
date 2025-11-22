#ifndef REQUEST_H
#define REQUEST_H

#include "types.h"
#include "utils.h"

struct Packet* parse_request_headers(char* buffer, ssize_t recv_len);

#endif /* REQUEST_H */