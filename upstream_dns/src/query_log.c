#include "query_log.h"
#include "config.h"
#include "utils.h"

#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <pwd.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/stat.h>

/* ---- Query counters ------------------------------------------------------ */

static _Atomic uint64_t g_qtype_counters[256];   /* [0] = qtype >= 256 */
static _Atomic uint64_t g_total_queries;

void count_query(uint16_t qtype)
{
    atomic_fetch_add(&g_total_queries, 1);
    atomic_fetch_add(&g_qtype_counters[qtype < 256 ? qtype : 0], 1);
}

void print_query_stats(void)
{
    printf("Query statistics:\n");
    printf("  Total queries: %" PRIu64 "\n", atomic_load(&g_total_queries));
    for (int i = 1; i < 256; i++) {
        uint64_t c = atomic_load(&g_qtype_counters[i]);
        if (c == 0) continue;
        const char* name = qtype_to_string((uint16_t)i);
        if (name) printf("  %-10s %" PRIu64 "\n", name, c);
        else      printf("  TYPE%-6d %" PRIu64 "\n", i, c);
    }
    uint64_t other = atomic_load(&g_qtype_counters[0]);
    if (other) printf("  %-10s %" PRIu64 "\n", "OTHER", other);
}

/* ---- CSV log: timestamp,client_ip,port,qtype,domain,rcode,info ------------ */
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int   g_log_fd    = -1;
static off_t g_log_bytes = 0;   /* bytes in the log since last truncate (g_log_mutex) */

/* Past this size the log is truncated in place (no rotation files). */
#define LOG_MAX_BYTES (20 * 1024 * 1024)

/* Open (O_APPEND) and seed g_log_bytes from the file size.  Caller holds
 * g_log_mutex.  Returns the fd or -1. */
static int log_open_locked(void) {
    int fd = path_open(LOG_FILE_PATH, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0) return -1;
    /* Still root and about to drop: hand the log to the drop user, or later
     * reopens (after the drop) fail on a root-owned 0644 file. */
    if (geteuid() == 0 && g_config.drop_user && *g_config.drop_user) {
        char u[128];
        snprintf(u, sizeof(u), "%s", g_config.drop_user);
        char *colon = strchr(u, ':');
        if (colon) *colon = '\0';
        struct passwd *pw = getpwnam(u);
        if (pw && fchown(fd, pw->pw_uid, pw->pw_gid) != 0) { /* best-effort */ }
    }
    struct stat st;
    g_log_bytes = (fstat(fd, &st) == 0) ? st.st_size : 0;
    return fd;
}

static const char* rcode_name(uint8_t rcode) {
    switch (rcode) {
        case RCODE_NO_ERROR:       return "NOERROR";
        case RCODE_FORMAT_ERROR:   return "FORMERR";
        case RCODE_SERVER_FAILURE: return "SERVFAIL";
        case RCODE_NAME_ERROR:     return "NXDOMAIN";
        case RCODE_NOTIMP:         return "NOTIMP";
        case RCODE_REFUSED:        return "REFUSED";
        case RCODE_NOTAUTH:        return "NOTAUTH";
        case RCODE_BADVERS:        return "BADVERS";
        default:                   return "ERR";
    }
}

/* Percent-encode control chars, non-ASCII, and , " \ % so attacker-chosen
 * names can't inject lines or columns.  Always NUL-terminates. */
static const char* csv_escape(const char* in, char* out, size_t out_size) {
    static const char hex[] = "0123456789ABCDEF";
    if (out_size == 0) return out;
    if (!in) { out[0] = '\0'; return out; }
    size_t o = 0;
    for (const unsigned char* p = (const unsigned char*)in; *p; p++) {
        unsigned char c = *p;
        int unsafe = (c < 0x20) || (c >= 0x7f) ||
                     c == ',' || c == '"' || c == '\\' || c == '%';
        if (unsafe) {
            if (o + 3 >= out_size) break;
            out[o++] = '%'; out[o++] = hex[c >> 4]; out[o++] = hex[c & 0xF];
        } else {
            if (o + 1 >= out_size) break;
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
    return out;
}

void log_query(const char* client_ip, uint16_t port,
               uint16_t qtype_val, const char* domain,
               uint8_t rcode, const char* info) {
    pthread_mutex_lock(&g_log_mutex);

    if (g_log_fd < 0) {
        g_log_fd = log_open_locked();
        if (g_log_fd < 0) {
            perror("Warning: Failed to open upstream log file");
            pthread_mutex_unlock(&g_log_mutex);
            return;
        }
    }

    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char ts[26];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);

    const char* qt = qtype_to_string(qtype_val);
    char qt_buf[12];
    if (!qt) { snprintf(qt_buf, sizeof(qt_buf), "TYPE%u", qtype_val); qt = qt_buf; }

    char dom_esc[512], info_esc[512];
    char line[512];
    int len = snprintf(line, sizeof(line), "%s,%s,%u,%s,%s,%s,%s\n",
                       ts, client_ip ? client_ip : "-", port,
                       qt, csv_escape(domain ? domain : "-", dom_esc, sizeof(dom_esc)),
                       rcode_name(rcode),
                       csv_escape(info ? info : "", info_esc, sizeof(info_esc)));

    /* snprintf reports the untruncated length: clamp, and keep the newline. */
    if (len > 0) {
        if (len >= (int)sizeof(line)) {
            len = (int)sizeof(line) - 1;
            line[len - 1] = '\n';
        }
        if (write(g_log_fd, line, len) < 0) {
            perror("Warning: Upstream log write failed");
        } else {
            /* O_APPEND: after truncation writes resume at offset 0. */
            g_log_bytes += len;
            if (g_log_bytes >= LOG_MAX_BYTES && ftruncate(g_log_fd, 0) == 0)
                g_log_bytes = 0;
        }
    }

    pthread_mutex_unlock(&g_log_mutex);
}

void log_close_upstream(void) {
    pthread_mutex_lock(&g_log_mutex);
    if (g_log_fd >= 0) { close(g_log_fd); g_log_fd = -1; }
    pthread_mutex_unlock(&g_log_mutex);
}

void log_reopen_upstream(void) {
    pthread_mutex_lock(&g_log_mutex);
    int fd = log_open_locked();
    if (fd >= 0) {
        if (g_log_fd >= 0) close(g_log_fd);
        g_log_fd = fd;
    } else {
        perror("Warning: log_reopen: Failed to open upstream log file; keeping current fd");
    }
    pthread_mutex_unlock(&g_log_mutex);
}
