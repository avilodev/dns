#include "utils.h"

#include <fcntl.h>
#include <pthread.h>
#include <sys/random.h>

/* ---- Pinned paths ---------------------------------------------------- */

#define MAX_PINS 32
typedef struct { char* path; char* base; int dirfd; } Pin;
static Pin g_pins[MAX_PINS];
static int g_pin_count = 0;
static pthread_mutex_t g_pin_lock = PTHREAD_MUTEX_INITIALIZER;

static int find_pin(const char* path)
{
    for (int i = 0; i < g_pin_count; i++)
        if (strcmp(g_pins[i].path, path) == 0) return i;
    return -1;
}

/* Parent directory of `path` into dir[cap]. */
static void parent_dir(const char* path, char* dir, size_t cap)
{
    const char* slash = strrchr(path, '/');
    if (!slash)             snprintf(dir, cap, ".");
    else if (slash == path) snprintf(dir, cap, "/");
    else                    snprintf(dir, cap, "%.*s", (int)(slash - path), path);
}

/* An already-pinned fd for `dir`, or -1.  Caller holds g_pin_lock.  Pins are
 * never closed, so sharing one dirfd between several files is safe. */
static int pinned_dirfd(const char* dir)
{
    char other[1024];
    for (int i = 0; i < g_pin_count; i++) {
        parent_dir(g_pins[i].path, other, sizeof(other));
        if (strcmp(other, dir) == 0) return g_pins[i].dirfd;
    }
    return -1;
}

void path_pin(const char* path)
{
    if (!path || !*path) return;
    pthread_mutex_lock(&g_pin_lock);
    if (find_pin(path) < 0 && g_pin_count < MAX_PINS) {
        const char* slash = strrchr(path, '/');
        char dir[1024];
        parent_dir(path, dir, sizeof(dir));

        /* Files in one directory share a single dirfd. */
        int fd = pinned_dirfd(dir);
        bool fresh = fd < 0;
        if (fresh) fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd >= 0) {
            char* p = strdup(path);
            char* b = strdup(slash ? slash + 1 : path);
            if (p && b) {
                g_pins[g_pin_count++] = (Pin){ p, b, fd };
            } else {
                free(p); free(b);
                if (fresh) close(fd);   /* a shared dirfd stays with its owner */
            }
        }
    }
    pthread_mutex_unlock(&g_pin_lock);
}

int path_open(const char* path, int flags, int mode)
{
    if (!path) return -1;
    pthread_mutex_lock(&g_pin_lock);
    int i = find_pin(path);
    int fd = i >= 0 ? openat(g_pins[i].dirfd, g_pins[i].base, flags | O_CLOEXEC, mode)
                    : open(path, flags | O_CLOEXEC, mode);
    pthread_mutex_unlock(&g_pin_lock);
    return fd;
}

/* ---- Randomness ------------------------------------------------------ */

int get_random_id(void)
{
    uint16_t id;
    if (getrandom(&id, sizeof(id), 0) == sizeof(id)) return id;
    return rand() & 0xFFFF;
}

int random_index(int n)
{
    if (n <= 0) return 0;                  /* no range to choose from */
    /* Rejection sampling: plain r % n is biased when 256 % n != 0. */
    int limit = 256 - 256 % n;
    for (int tries = 0; tries < 16; tries++) {
        uint8_t r;
        if (getrandom(&r, sizeof(r), 0) != sizeof(r)) break;
        if (r < limit) return r % n;
    }
    return rand() % n;
}

const char* qtype_to_string(uint16_t qtype)
{
    switch (qtype) {
        case QTYPE_A:          return "A";
        case QTYPE_NS:         return "NS";
        case QTYPE_CNAME:      return "CNAME";
        case QTYPE_SOA:        return "SOA";
        case QTYPE_PTR:        return "PTR";
        case QTYPE_MX:         return "MX";
        case QTYPE_TXT:        return "TXT";
        case QTYPE_AAAA:       return "AAAA";
        case QTYPE_SRV:        return "SRV";
        case QTYPE_HTTPS:      return "HTTPS";
        case QTYPE_DS:         return "DS";
        case QTYPE_RRSIG:      return "RRSIG";
        case QTYPE_NSEC:       return "NSEC";
        case QTYPE_DNSKEY:     return "DNSKEY";
        case QTYPE_NSEC3:      return "NSEC3";
        case QTYPE_NSEC3PARAM: return "NSEC3PARAM";
        case QTYPE_ANY:        return "ANY";
        default:               return NULL;
    }
}

/* ---- Sockets --------------------------------------------------------- */

static bool write_all(int fd, const void* buf, size_t len)
{
    const uint8_t* p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) return false;
        p += n;
        len -= (size_t)n;
    }
    return true;
}

/* One write: a separate 2-byte prefix can stall on Nagle + delayed ACK. */
bool tcp_send_msg(int fd, const void* msg, size_t len)
{
    uint8_t* buf = malloc(len + 2);
    if (!buf) return false;
    wr16(buf, (uint16_t)len);
    memcpy(buf + 2, msg, len);
    bool ok = write_all(fd, buf, len + 2);
    free(buf);
    return ok;
}

socklen_t sockaddr_from_ip(const char* ip, uint16_t port, struct sockaddr_storage* out)
{
    memset(out, 0, sizeof(*out));
    struct sockaddr_in*  s4 = (struct sockaddr_in*)out;
    struct sockaddr_in6* s6 = (struct sockaddr_in6*)out;
    if (inet_pton(AF_INET, ip, &s4->sin_addr) == 1) {
        s4->sin_family = AF_INET;
        s4->sin_port   = htons(port);
        return sizeof(*s4);
    }
    if (inet_pton(AF_INET6, ip, &s6->sin6_addr) == 1) {
        s6->sin6_family = AF_INET6;
        s6->sin6_port   = htons(port);
        return sizeof(*s6);
    }
    return 0;
}

void sockaddr_to_ip(const struct sockaddr_storage* ss, char* ip, uint16_t* port)
{
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6* s6 = (const struct sockaddr_in6*)ss;
        inet_ntop(AF_INET6, &s6->sin6_addr, ip, INET6_ADDRSTRLEN);
        if (port) *port = ntohs(s6->sin6_port);
    } else {
        const struct sockaddr_in* s4 = (const struct sockaddr_in*)ss;
        inet_ntop(AF_INET, &s4->sin_addr, ip, INET6_ADDRSTRLEN);
        if (port) *port = ntohs(s4->sin_port);
    }
}
