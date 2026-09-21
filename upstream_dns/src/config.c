#include "config.h"
#include "dns_name.h"
#include "dnssec_wire.h"
#include "infra.h"
#include "utils.h"

#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <strings.h>
#include <openssl/evp.h>

/* ---- Command line ------------------------------------------------------ */

/* Replace a string option, freeing any previous value (the flag may repeat). */
static bool set_str(char** dst, const char* val)
{
    char* copy = strdup(val);
    if (!copy) { fprintf(stderr, "Out of memory parsing options\n"); return false; }
    free(*dst);
    *dst = copy;
    return true;
}

/* Parse a bounded integer flag.  Returns false (with a message) if invalid. */
static bool parse_int(const char* arg, long lo, long hi, const char* what, int* out)
{
    char* end;
    long v = strtol(arg, &end, 10);
    if (*end != '\0' || v < lo || v > hi) {
        fprintf(stderr, "Invalid %s: %s\n", what, arg);
        return false;
    }
    *out = (int)v;
    return true;
}

int load_config(int argc, char** argv)
{
    g_config = (Config){ .port = PORT, .thread_count = NUM_THREADS, .queue_size = QUEUE_SIZE };

    int opt;
    while ((opt = getopt(argc, argv, "p:t:q:b:a:r:U:")) != -1) {
        bool ok = true;
        switch (opt) {
        case 'p': ok = parse_int(optarg, 1, 65535, "port", &g_config.port); break;
        case 't': ok = parse_int(optarg, 1, 1024, "thread count", &g_config.thread_count); break;
        case 'q': ok = parse_int(optarg, 1, 1048576, "queue size", &g_config.queue_size); break;
        case 'r': ok = parse_int(optarg, 0, 1000000, "rate limit", &g_config.rate_limit_qps); break;
        case 'b': ok = set_str(&g_config.bind_addr, optarg); break;
        case 'a': ok = set_str(&g_config.acl_csv,   optarg); break;
        case 'U': ok = set_str(&g_config.drop_user, optarg); break;
        default:  ok = false;
        }
        if (!ok) return -1;
    }
    printf("Config: port=%d threads=%d queue=%d\n",
           g_config.port, g_config.thread_count, g_config.queue_size);
    return 0;
}

/* ---- Listeners --------------------------------------------------------- */

int create_listener(int family, int type, int port, bool fatal)
{
    const char* what = type == SOCK_DGRAM ? (family == AF_INET ? "UDP IPv4" : "UDP IPv6")
                                          : (family == AF_INET ? "TCP IPv4" : "TCP IPv6");
    struct sockaddr_storage ss;
    socklen_t slen = sockaddr_from_ip(g_config.bind_addr ? g_config.bind_addr
                                      : family == AF_INET ? "0.0.0.0" : "::", (uint16_t)port, &ss);
    if (slen == 0 || ss.ss_family != family) return -1;   /* -b is the other family */

    int one = 1;
    int sock = socket(family, type, 0);
    if (sock < 0) goto fail;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (type == SOCK_DGRAM)
        setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    if (family == AF_INET6)
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    if (bind(sock, (struct sockaddr*)&ss, slen) < 0) goto fail;
    if (type == SOCK_STREAM && listen(sock, SOMAXCONN) < 0) goto fail;

    char ip[INET6_ADDRSTRLEN];
    sockaddr_to_ip(&ss, ip, NULL);
    printf(family == AF_INET ? "DNS Server listening on %s:%d (%s)\n"
                             : "DNS Server listening on [%s]:%d (%s)\n", ip, port, what);
    return sock;

fail:
    fprintf(stderr, "%s: %s listener on port %d: %s\n", fatal ? "Error" : "Warning",
            what, port, strerror(errno));
    if (sock >= 0) close(sock);
    if (fatal) exit(EXIT_FAILURE);
    return -1;
}

/* ---- Root hints -------------------------------------------------------- */

typedef struct {
    char name[256];
    char ip[INET6_ADDRSTRLEN];   /* IPv4 glue; "" if none */
} RootHint;

/* Read by every worker, replaced on SIGHUP: copy in/out under the lock. */
static RootHint         g_hints[ROOT_SERVERS];
static pthread_rwlock_t g_hints_lock = PTHREAD_RWLOCK_INITIALIZER;

static void install_hints(const RootHint* table)
{
    pthread_rwlock_wrlock(&g_hints_lock);
    memcpy(g_hints, table, sizeof(g_hints));
    pthread_rwlock_unlock(&g_hints_lock);
}

/* Parse `dig . NS` style output.  Addresses are matched to NS names by owner
 * afterwards (dig lists all NS before any glue).  Only a table with at least
 * one IPv4 address replaces the current one. */
int load_hints(const char* filename)
{
    int fd = path_open(filename, O_RDONLY, 0);
    FILE* fp = fd >= 0 ? fdopen(fd, "r") : NULL;
    if (!fp) {
        if (fd >= 0) close(fd);
        perror("Failed to open hints file");
        return -1;
    }

    RootHint t[ROOT_SERVERS] = {0};
    int ns_count = 0;
    struct { char owner[256]; char ip[INET6_ADDRSTRLEN]; } v4[64];
    int nv4 = 0;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char tok[5][256];
        int ntok = sscanf(line, "%255s %255s %255s %255s %255s",
                          tok[0], tok[1], tok[2], tok[3], tok[4]);
        if (ntok < 3 || tok[0][0] == ';') continue;

        /* owner [ttl] [IN] type value */
        int k = 1;
        if (isdigit((unsigned char)tok[k][0])) k++;
        if (k < ntok && strcasecmp(tok[k], "IN") == 0) k++;
        if (k + 1 >= ntok) continue;
        const char* rtype = tok[k];
        const char* value = tok[k + 1];

        if (strcmp(tok[0], ".") == 0 && strcasecmp(rtype, "NS") == 0) {
            if (ns_count < ROOT_SERVERS)
                snprintf(t[ns_count++].name, sizeof(t[0].name), "%s", value);
        } else if (strcasecmp(rtype, "A") == 0 && nv4 < (int)(sizeof(v4) / sizeof(v4[0]))) {
            snprintf(v4[nv4].owner, sizeof(v4[0].owner), "%s", tok[0]);
            snprintf(v4[nv4].ip, sizeof(v4[0].ip), "%s", value);
            nv4++;
        }
    }
    fclose(fp);

    int usable = 0;
    for (int i = 0; i < ns_count; i++) {
        for (int j = 0; j < nv4 && !t[i].ip[0]; j++)      /* first match wins */
            if (dname_is_subdomain(v4[j].owner, t[i].name) &&
                dname_is_subdomain(t[i].name, v4[j].owner))
                snprintf(t[i].ip, sizeof(t[i].ip), "%s", v4[j].ip);
        if (t[i].ip[0]) usable++;
    }
    if (usable == 0) {
        fprintf(stderr, "Hints file %s yielded no usable root servers; keeping current hints\n",
                filename);
        return -1;
    }
    install_hints(t);
    return ns_count;
}

/* Fallback when the hints file is missing: IANA root addresses (2024). */
int load_hints_builtin(void)
{
    static const char* ips[ROOT_SERVERS] = {
        "198.41.0.4",   "170.247.170.2", "192.33.4.12",   "199.7.91.13",
        "192.203.230.10", "192.5.5.241", "192.112.36.4",  "198.97.190.53",
        "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
        "202.12.27.33",
    };
    RootHint t[ROOT_SERVERS];
    for (int i = 0; i < ROOT_SERVERS; i++) {
        snprintf(t[i].name, sizeof(t[i].name), "%c.root-servers.net.", 'a' + i);
        snprintf(t[i].ip, sizeof(t[i].ip), "%s", ips[i]);
    }
    install_hints(t);
    return ROOT_SERVERS;
}

/* Lowest infra_score() wins; the score's jitter spreads load across near-equal
 * roots, and the random start breaks remaining ties. */
char* hints_random_root_ip(void)
{
    char best[INET6_ADDRSTRLEN] = "";
    int best_score = 0;
    int start = random_index(ROOT_SERVERS);
    pthread_rwlock_rdlock(&g_hints_lock);
    for (int k = 0; k < ROOT_SERVERS; k++) {
        const RootHint* h = &g_hints[(start + k) % ROOT_SERVERS];
        if (!h->ip[0]) continue;
        int sc = infra_score(h->ip);
        if (!best[0] || sc < best_score) {
            memcpy(best, h->ip, sizeof(best));
            best_score = sc;
        }
    }
    pthread_rwlock_unlock(&g_hints_lock);
    return best[0] ? strdup(best) : NULL;
}

int hints_copy_names(char names[ROOT_SERVERS][256])
{
    int n = 0;
    pthread_rwlock_rdlock(&g_hints_lock);
    for (int i = 0; i < ROOT_SERVERS; i++)
        if (g_hints[i].name[0])
            memcpy(names[n++], g_hints[i].name, 256);
    pthread_rwlock_unlock(&g_hints_lock);
    return n;
}

/* ---- Trust anchors ----------------------------------------------------- */

TrustAnchor* load_trust_anchors(const char* filename)
{
    /* Through the pin, like the hints file: a plain open() cannot traverse a
     * non-searchable ancestor once privileges have been dropped. */
    int fd = path_open(filename, O_RDONLY, 0);
    FILE* fp = fd >= 0 ? fdopen(fd, "r") : NULL;
    if (!fp) {
        if (fd >= 0) close(fd);
        perror("Warning: Cannot open trust anchor file");
        return NULL;
    }

    TrustAnchor* head = NULL;
    TrustAnchor** tail = &head;
    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        char owner[256], class_str[8], rtype[16], b64[4096];
        int ttl;
        unsigned flags, protocol, algorithm;
        if (line[strspn(line, " \t")] == '#' ||
            sscanf(line, "%255s %d %7s %15s %u %u %u %4095s", owner, &ttl, class_str,
                   rtype, &flags, &protocol, &algorithm, b64) < 8 ||
            owner[0] == ';' || strcasecmp(rtype, "DNSKEY") != 0)
            continue;

        size_t b64_len = strlen(b64);
        uint8_t* key = malloc(b64_len * 3 / 4 + 4);
        int n = key ? EVP_DecodeBlock(key, (const unsigned char*)b64, (int)b64_len) : -1;
        if (n <= 0) {
            free(key);
            fprintf(stderr, "Warning: Failed to base64-decode trust anchor key for %s\n", owner);
            continue;
        }
        /* EVP_DecodeBlock counts '=' padding as output bytes. */
        for (size_t i = b64_len; i > 0 && b64[i - 1] == '='; i--) n--;

        TrustAnchor* ta = calloc(1, sizeof(*ta));
        if (!ta) { free(key); continue; }
        snprintf(ta->owner, sizeof(ta->owner), "%s", owner);
        ta->flags      = (uint16_t)flags;
        ta->protocol   = (uint8_t)protocol;
        ta->algorithm  = (uint8_t)algorithm;
        ta->pubkey     = key;
        ta->pubkey_len = (uint16_t)n;
        ta->key_tag    = compute_key_tag(ta->flags, ta->protocol, ta->algorithm, key, ta->pubkey_len);
        *tail = ta;
        tail = &ta->next;
        printf("Loaded trust anchor: %s DNSKEY flags=%u alg=%u key_tag=%u\n",
               owner, ta->flags, ta->algorithm, ta->key_tag);
    }
    fclose(fp);
    return head;
}

void free_trust_anchors(TrustAnchor* anchors)
{
    while (anchors) {
        TrustAnchor* next = anchors->next;
        free(anchors->pubkey);
        free(anchors);
        anchors = next;
    }
}
