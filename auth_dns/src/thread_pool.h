#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <pthread.h>
#include <stdbool.h>

// Forward declarations
struct ThreadPool;
struct WorkItem;

// Work function signature
typedef void* (*work_func_t)(void* arg);

// Configuration
struct ThreadPoolConfig {
    int num_threads;        // Number of worker threads
    int max_queue_size;     // Max pending work items (0 = unlimited)
};

// Statistics
struct ThreadPoolStats {
    int active_threads;
    int queued_work;
    unsigned long long completed_work;
    unsigned long long rejected_work;
};

// Thread pool operations
struct ThreadPool* threadpool_create(struct ThreadPoolConfig config);
int threadpool_add_work(struct ThreadPool* pool, work_func_t func, void* arg);
void threadpool_wait(struct ThreadPool* pool);
void threadpool_destroy(struct ThreadPool* pool);
void threadpool_get_stats(struct ThreadPool* pool, struct ThreadPoolStats* stats);

/* True when work is queued behind the busy workers (someone is waiting). */
bool threadpool_has_waiting(struct ThreadPool* pool);

#endif