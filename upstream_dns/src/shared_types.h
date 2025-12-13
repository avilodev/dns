#ifndef SHARED_TYPES_H
#define SHARED_TYPES_H

#define MAX_CNAME_DEPTH 10 

typedef struct {
    char* domains[MAX_CNAME_DEPTH];
    int count;
} CnameChain;

typedef struct {
    struct {
        char* name;           // CNAME owner
        char* target;         // CNAME target
        uint32_t ttl;
        unsigned char* rdata;
        size_t rdata_len;
    } entries[MAX_CNAME_DEPTH];
    int count;
} CnameChainData;

#endif /* SHARED_TYPES_H */
