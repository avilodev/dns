#include "utils.h"
#include "dns_name.h"
#include <sys/random.h>
#include <fcntl.h>
#include <pthread.h>

/* ---- Pinned paths (see utils.h) ---------------------------------------- */

#define MAX_PINS 8
static struct { char* path; char* base; int dirfd; } g_pins[MAX_PINS];
static int g_pin_count = 0;
static pthread_mutex_t g_pin_lock = PTHREAD_MUTEX_INITIALIZER;

void path_pin(const char* path)
{
    if (!path || !*path) return;
    pthread_mutex_lock(&g_pin_lock);
    for (int i = 0; i < g_pin_count; i++)
        if (strcmp(g_pins[i].path, path) == 0) { pthread_mutex_unlock(&g_pin_lock); return; }
    if (g_pin_count < MAX_PINS) {
        const char* slash = strrchr(path, '/');
        char dir[1024];
        if (!slash)            snprintf(dir, sizeof(dir), ".");
        else if (slash == path) snprintf(dir, sizeof(dir), "/");
        else                   snprintf(dir, sizeof(dir), "%.*s", (int)(slash - path), path);
        int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd >= 0) {
            g_pins[g_pin_count].path  = strdup(path);
            g_pins[g_pin_count].base  = strdup(slash ? slash + 1 : path);
            g_pins[g_pin_count].dirfd = fd;
            if (g_pins[g_pin_count].path && g_pins[g_pin_count].base) g_pin_count++;
            else { free(g_pins[g_pin_count].path); free(g_pins[g_pin_count].base); close(fd); }
        }
    }
    pthread_mutex_unlock(&g_pin_lock);
}

int path_open(const char* path, int flags, int mode)
{
    if (!path) return -1;
    pthread_mutex_lock(&g_pin_lock);
    for (int i = 0; i < g_pin_count; i++) {
        if (strcmp(g_pins[i].path, path) == 0) {
            int fd = openat(g_pins[i].dirfd, g_pins[i].base, flags | O_CLOEXEC, mode);
            pthread_mutex_unlock(&g_pin_lock);
            return fd;
        }
    }
    pthread_mutex_unlock(&g_pin_lock);
    return open(path, flags | O_CLOEXEC, mode);
}

int get_random_id(void)
{
    uint16_t id;
    if (getrandom(&id, sizeof(id), 0) == sizeof(id)) {
        return id;
    }
    // fallback if getrandom fails
    return rand() & 0xFFFF;
}

int get_random_server(void)
{
    uint8_t r;
    if (getrandom(&r, sizeof(r), 0) == sizeof(r)) {
        return r % 13;
    }
    return rand() % 13;
}

/*
 * Convert QTYPE to name string.  Returns NULL for unrecognised types so
 * callers can fall back to a "TYPE%u" numeric format.
 */
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
        case 33:               return "SRV";
        case QTYPE_DS:         return "DS";
        case QTYPE_RRSIG:      return "RRSIG";
        case QTYPE_NSEC:       return "NSEC";
        case QTYPE_DNSKEY:     return "DNSKEY";
        case QTYPE_NSEC3:      return "NSEC3";
        case QTYPE_NSEC3PARAM: return "NSEC3PARAM";
        case 255:              return "ANY";
        default:               return NULL;
    }
}

/*
 * Bailiwick test (cache-poisoning defence, RFC 2181 §5.4.1).
 *
 * Return true when `name` is at or below `zone` in the DNS hierarchy — i.e.
 * name == zone, or name is a proper subdomain of zone — comparing
 * label-by-label and case-insensitively (DNS names are case-insensitive,
 * RFC 1035 §3.1).
 *
 * Both arguments are presentation-form names with no trailing dot
 * (e.g. "www.example.com", "example.com"); a single trailing dot is tolerated.
 * The root zone, represented by "" or ".", is the bailiwick of every name.
 *
 *   name_in_bailiwick("www.example.com", "example.com") == true
 *   name_in_bailiwick("example.com",     "example.com") == true   (equal)
 *   name_in_bailiwick("evil.com",        "paypal.com")  == false
 *   name_in_bailiwick("notexample.com",  "example.com") == false  (label boundary)
 *   name_in_bailiwick("anything.com",    "")            == true   (root)
 */
bool name_in_bailiwick(const char* name, const char* zone)
{
    /* Label-aligned, case-insensitive and escape-aware (dns_name.c). */
    return dname_is_subdomain(name, zone);
}
