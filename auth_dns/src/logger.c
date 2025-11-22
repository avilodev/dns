#include "logger.h"
#include <pthread.h>

// Global mutex for log file access
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Log DNS query to file with resolved IP (Thread-Safe)
 */
int log_entry(const char* client_ip, uint16_t port, const char* domain, const char* resolved_ip) {
    char log_file_path[256];
    sprintf(log_file_path, "%s", LOG_FILE_PATH);

    // Lock before accessing file
    pthread_mutex_lock(&log_mutex);

    int fd = open(log_file_path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0) {
        perror("Warning: Failed to open log file");
        pthread_mutex_unlock(&log_mutex);
        return -1;
    }

    char log_line[512];
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    int len;
    if (resolved_ip) {
        len = snprintf(log_line, sizeof(log_line), "[%s] %s:%u - %s -> %s\n",
                      timestamp, client_ip, port, domain ? domain : "unknown", resolved_ip);
    } else {
        len = snprintf(log_line, sizeof(log_line), "[%s] %s:%u - %s\n",
                      timestamp, client_ip, port, domain ? domain : "error");
    }
    
    if (write(fd, log_line, len) < 0) {
        perror("Warning: Log write failed");
    }

    close(fd);
    
    // Unlock after file operations complete
    pthread_mutex_unlock(&log_mutex);
    
    return 0;
}