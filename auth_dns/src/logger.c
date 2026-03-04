#include "logger.h"
#include <pthread.h>

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int log_fd = -1;

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
 * Format: [timestamp] client_ip:port QTYPE domain RCODE [-> info]
 */
int log_entry(const char* client_ip, uint16_t port, uint16_t qtype,
              const char* domain, uint8_t rcode, const char* info) {
    pthread_mutex_lock(&log_mutex);

    // Open the log file lazily and keep it open for the server's lifetime
    if (log_fd < 0) {
        log_fd = open(LOG_FILE_PATH, O_CREAT | O_WRONLY | O_APPEND, 0644);
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

    char log_line[512];
    int len;
    if (info) {
        len = snprintf(log_line, sizeof(log_line), "[%s] %s:%u %s %s %s -> %s\n",
                       timestamp, client_ip ? client_ip : "-", port,
                       qt, domain ? domain : "-",
                       rcode_name(rcode), info);
    } else {
        len = snprintf(log_line, sizeof(log_line), "[%s] %s:%u %s %s %s\n",
                       timestamp, client_ip ? client_ip : "-", port,
                       qt, domain ? domain : "-",
                       rcode_name(rcode));
    }

    if (len > 0 && write(log_fd, log_line, len) < 0) {
        perror("Warning: Log write failed");
    }

    pthread_mutex_unlock(&log_mutex);
    return 0;
}

/**
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
