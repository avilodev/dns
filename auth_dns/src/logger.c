#include "logger.h"
#include <pthread.h>
#include <pwd.h>

extern Config g_config;

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int log_fd = -1;

/* Open the query log (O_APPEND).  If we still hold root and a privilege drop is
 * configured (-U), hand the file to that user now so reopens AFTER the drop
 * (SIGHUP / logrotate) succeed instead of failing EACCES on a 0644 log it does
 * not own.  Returns the fd, or -1 on failure. */
static int open_log_fd(void) {
    int fd = open(LOG_FILE_PATH, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0) return -1;
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
    return fd;
}

/* Exported — also used by main.c print_qtype_stats(). Returns NULL for unknown. */
const char* qtype_name(uint16_t qtype) {
    switch (qtype) {
        case 1:   return "A";
        case 2:   return "NS";
        case 5:   return "CNAME";
        case 6:   return "SOA";
        case 12:  return "PTR";
        case 15:  return "MX";
        case 16:  return "TXT";
        case 28:  return "AAAA";
        case 33:  return "SRV";
        case 43:  return "DS";
        case 46:  return "RRSIG";
        case 47:  return "NSEC";
        case 48:  return "DNSKEY";
        case 50:  return "NSEC3";
        case 51:  return "NSEC3PARAM";
        case 255: return "ANY";
        default:  return NULL;
    }
}

/*
 * Percent-encode CSV-unsafe bytes (known_issues 4.6).  DNS labels may contain
 * arbitrary octets — commas, quotes, control chars, even newlines — and the
 * QNAME and answer fields are attacker-influenced.  Encoding control chars,
 * the CSV structural characters (comma, double-quote), backslash, percent, and
 * any non-ASCII byte as %XX prevents log-line injection and column-splitting
 * while leaving ordinary names readable.  Always NUL-terminates.
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

static const char* rcode_name(uint8_t rcode) {
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
 * Log a DNS query result (thread-safe).
 * Keeps the log fd open for the server's lifetime to avoid per-query open/close overhead.
 * Format (CSV): timestamp,client_ip,port,qtype,domain,rcode,info
 * The info column is empty when there is no answer detail.
 */
int log_entry(const char* client_ip, uint16_t port, uint16_t qtype,
              const char* domain, uint8_t rcode, const char* info) {
    pthread_mutex_lock(&log_mutex);

    // Open the log file lazily and keep it open for the server's lifetime
    if (log_fd < 0) {
        log_fd = open_log_fd();
        if (log_fd < 0) {
            perror("Warning: Failed to open log file");
            pthread_mutex_unlock(&log_mutex);
            return -1;
        }
    }

    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);           // thread-safe vs localtime()
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_buf);

    const char* qt = qtype_name(qtype);
    char qt_buf[12];
    if (!qt) { snprintf(qt_buf, sizeof(qt_buf), "TYPE%u", qtype); qt = qt_buf; }

    /* CSV: timestamp,client_ip,port,qtype,domain,rcode,info  (info empty if none).
     * domain (QNAME) and info (answer data) are attacker-influenced — escape
     * them so they cannot inject newlines or commas (4.6). */
    char dom_esc[512], info_esc[512];
    char log_line[512];
    int len = snprintf(log_line, sizeof(log_line), "%s,%s,%u,%s,%s,%s,%s\n",
                       timestamp, client_ip ? client_ip : "-", port,
                       qt, csv_escape(domain ? domain : "-", dom_esc, sizeof(dom_esc)),
                       rcode_name(rcode),
                       csv_escape(info ? info : "", info_esc, sizeof(info_esc)));

    /* snprintf returns the number of bytes it WOULD have written, even when
     * it truncated.  Without clamping, write() reads past the end of log_line
     * and writes uninitialized stack memory to the log (and the trailing '\n'
     * gets lost, causing log entries to run together). */
    if (len > 0) {
        if (len >= (int)sizeof(log_line)) len = (int)sizeof(log_line) - 1;
        if (write(log_fd, log_line, len) < 0)
            perror("Warning: Log write failed");
    }

    pthread_mutex_unlock(&log_mutex);
    return 0;
}

/*
 * Close the persistent log file descriptor.
 * Call once on server shutdown; safe to call if never opened.
 */
void log_close(void) {
    pthread_mutex_lock(&log_mutex);
    if (log_fd >= 0) {
        close(log_fd);
        log_fd = -1;
    }
    pthread_mutex_unlock(&log_mutex);
}

/*
 * Reopen the log file.  Call after logrotate has moved/truncated the old file
 * (triggered by SIGHUP in the main loop).  Thread-safe.
 */
void log_reopen(void) {
    pthread_mutex_lock(&log_mutex);
    if (log_fd >= 0) { close(log_fd); log_fd = -1; }
    log_fd = open_log_fd();
    if (log_fd < 0) perror("Warning: log_reopen: Failed to open log file");
    pthread_mutex_unlock(&log_mutex);
}
