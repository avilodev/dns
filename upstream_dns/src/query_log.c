#include "query_log.h"
#include "config.h"
#include "diag.h"
#include "utils.h"

#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <pwd.h>
#include <stdatomic.h>
#include <strings.h>
#include <time.h>
#include <sys/stat.h>

/* ---- Diagnostic level ----------------------------------------------------- */

/* Definition for diag.h.  Warnings and errors by default: per-query chatter
 * (DIAG_DEBUG) is what used to fill the launcher log. */
int g_diag_level = DIAG_WARN;

static const char* const k_diag_names[] = { "error", "warn", "info", "debug" };

int diag_level_from_name(const char* name)
{
    if (!name) return -1;
    for (int i = 0; i < (int)(sizeof(k_diag_names) / sizeof(k_diag_names[0])); i++)
        if (strcasecmp(name, k_diag_names[i]) == 0) return i;
    return -1;
}

const char* diag_level_name(int level)
{
    if (level < 0 || level > DIAG_DEBUG) return "?";
    return k_diag_names[level];
}

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

/*
 * Last-resort cap for a deployment where cron_scripts/dns_log was never
 * installed.  Deliberately set ABOVE anything the daily archiver leaves
 * behind, so this is a backstop rather than a competitor to it.
 *
 * On hitting it we rotate to LOG_ROTATED_PATH and reopen, keeping one
 * generation — the old behaviour (ftruncate to 0) discarded the entire
 * history in a single write, with nothing archived and no warning.
 */
#define LOG_MAX_BYTES    (64 * 1024 * 1024)
#define LOG_ROTATED_PATH LOG_FILE_PATH ".0"

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

/* Pin the log and its rotation slot while still root, so both the reopen and
 * the renameat below work as the drop user under a 0700 ancestor. */
void log_pin_paths(void)
{
    path_pin(LOG_FILE_PATH);
    path_pin(LOG_ROTATED_PATH);
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

/*
 * Enforce LOG_MAX_BYTES.  Caller holds g_log_mutex.
 *
 * Preferred path: rename the full log aside and open a fresh one, keeping one
 * generation.  Creating that fresh file needs write permission on the log
 * DIRECTORY, which the drop user does not have under the default install
 * (logs/ is owned by the invoking user, mode 0755) — so when the reopen
 * fails we put the old name back and fall back to truncating in place.
 * Either way the log stops growing; only the retained generation is lost.
 */
static void log_enforce_cap_locked(void)
{
    /* The daily archiver may have rotated behind us, leaving the counter
     * stale-high; re-stat before discarding anything. */
    struct stat st;
    if (fstat(g_log_fd, &st) == 0) g_log_bytes = st.st_size;
    if (g_log_bytes < LOG_MAX_BYTES) return;

    if (path_rename(LOG_FILE_PATH, LOG_ROTATED_PATH) == 0) {
        int fd = log_open_locked();
        if (fd >= 0) {
            close(g_log_fd);
            g_log_fd = fd;          /* log_open_locked reseeded g_log_bytes */
            return;
        }
        /* Could not create the replacement: undo, so we keep writing to a
         * file that still has the name everything else expects. */
        (void)path_rename(LOG_ROTATED_PATH, LOG_FILE_PATH);
    }
    if (ftruncate(g_log_fd, 0) == 0) g_log_bytes = 0;
}

void log_query(const char* client_ip, uint16_t port,
               uint16_t qtype_val, const char* domain,
               uint8_t rcode, const char* info) {
    pthread_mutex_lock(&g_log_mutex);

    /* Complain once per outage, not once per query: this runs on the hot path,
     * and a spell of EACCES on the log once wrote 4864 identical lines into
     * the launcher log. */
    static bool open_failed = false;
    if (g_log_fd < 0) {
        g_log_fd = log_open_locked();
        if (g_log_fd < 0) {
            if (!open_failed) {
                open_failed = true;
                perror("Error: Cannot open upstream log file");
            }
            pthread_mutex_unlock(&g_log_mutex);
            return;
        }
        if (open_failed) {
            open_failed = false;
            fprintf(stderr, "Upstream log reopened: %s\n", LOG_FILE_PATH);
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
        static bool write_failed = false;   /* guarded by the log mutex */
        if (write(g_log_fd, line, len) < 0) {
            /* Once per outage (e.g. disk full), not once per query. */
            if (!write_failed) perror("Warning: Upstream log write failed");
            write_failed = true;
        } else {
            write_failed = false;
            /* O_APPEND: after truncation writes resume at offset 0. */
            g_log_bytes += len;
            if (g_log_bytes >= LOG_MAX_BYTES) log_enforce_cap_locked();
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
