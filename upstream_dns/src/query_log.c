#include "query_log.h"

#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>

#include "types.h"
#include "utils.h"   /* qtype_to_string */

/* Defined in main.c; the logger reads only drop_user (for log fd ownership). */
extern Config g_config;

/* --------------------------------------------------------------------------
 * Simple query logger — persistent fd, localtime_r, mutex-protected.
 * Format (CSV): timestamp,client_ip,port,qtype,domain,rcode,info
 * The info column is empty when there is no answer detail.
 * -------------------------------------------------------------------------- */
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int   g_log_fd    = -1;
static off_t g_log_bytes = 0;   /* bytes in the log since last truncate (g_log_mutex) */

/* Cap upstream.log at this size.  When it is exceeded the log is truncated in
 * place (ftruncate to 0) — no rotation, no upstream.log.1, no other file is
 * ever created.  Replaces the previous logrotate-based rotation. */
#define LOG_MAX_BYTES (20 * 1024 * 1024)

/* Open the log file (O_APPEND) and seed g_log_bytes from its current size so the
 * in-place cap accounts for bytes already on disk.  Caller holds g_log_mutex.
 * Returns the fd, or -1 on failure. */
static int log_open_locked(void) {
    int fd = open(LOG_FILE_PATH, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0) return -1;
    /* If we still hold root and will drop to an unprivileged user, hand the log
     * to that user now.  Later reopens (SIGHUP/logrotate) run AFTER the drop, so
     * without this they fail with EACCES on a root-owned 0644 log. */
    if (geteuid() == 0 && g_config.drop_user && *g_config.drop_user) {
        char u[128];
        snprintf(u, sizeof(u), "%s", g_config.drop_user);
        char *colon = strchr(u, ':');
        if (colon) *colon = '\0';
        struct passwd *pw = getpwnam(u);
        if (pw && fchown(fd, pw->pw_uid, pw->pw_gid) != 0) {
            /* best-effort: the fd we just opened still works regardless */
        }
    }
    struct stat st;
    g_log_bytes = (fstat(fd, &st) == 0) ? st.st_size : 0;
    return fd;
}

static const char* rcode_name_up(uint8_t rcode) {
    switch (rcode) {
        case 0:  return "NOERROR";
        case 1:  return "FORMERR";
        case 2:  return "SERVFAIL";
        case 3:  return "NXDOMAIN";
        case 4:  return "NOTIMP";
        case 5:  return "REFUSED";
        case 9:  return "NOTAUTH";
        case 16: return "BADVERS";
        default: return "ERR";
    }
}

/*
 * Percent-encode CSV-unsafe bytes (known_issues 4.6).  The QNAME and answer
 * fields are attacker-influenced and DNS labels may carry arbitrary octets;
 * encoding control chars, commas, double-quotes, backslash, percent, and
 * non-ASCII bytes as %XX prevents log-line injection / column-splitting while
 * keeping ordinary names readable.  Always NUL-terminates.
 */
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

    /* CSV: timestamp,client_ip,port,qtype,domain,rcode,info  (info empty if none).
     * domain (QNAME) and info (answer data) are attacker-influenced — escape
     * them so they cannot inject newlines or commas (4.6). */
    char dom_esc[512], info_esc[512];
    char line[512];
    int len = snprintf(line, sizeof(line), "%s,%s,%u,%s,%s,%s,%s\n",
                       ts, client_ip ? client_ip : "-", port,
                       qt, csv_escape(domain ? domain : "-", dom_esc, sizeof(dom_esc)),
                       rcode_name_up(rcode),
                       csv_escape(info ? info : "", info_esc, sizeof(info_esc)));

    /* snprintf returns the number of bytes it WOULD have written, even when
     * it truncated.  Without clamping, write() reads past the end of line[]
     * and writes uninitialized stack memory to the log (and the trailing '\n'
     * gets lost, causing log entries to run together). */
    if (len > 0) {
        if (len >= (int)sizeof(line)) len = (int)sizeof(line) - 1;
        if (write(g_log_fd, line, len) < 0) {
            perror("Warning: Upstream log write failed");
        } else {
            /* In-place size cap: once the log passes LOG_MAX_BYTES, truncate it
             * back to empty.  O_APPEND means the next write resumes at offset 0,
             * so the file is reset in place and no other file is ever created. */
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
    if (g_log_fd >= 0) { close(g_log_fd); g_log_fd = -1; }
    g_log_fd = log_open_locked();
    if (g_log_fd < 0) perror("Warning: log_reopen: Failed to open upstream log file");
    pthread_mutex_unlock(&g_log_mutex);
}
