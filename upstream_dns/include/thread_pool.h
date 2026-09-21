#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <pthread.h>
#include <stdbool.h>

struct ThreadPool;

typedef void* (*work_func_t)(void* arg);

struct ThreadPoolConfig {
    int num_threads;
    int max_queue_size;     /* 0 = unlimited */
};

struct ThreadPool* threadpool_create(struct ThreadPoolConfig config);

/* Queue work.  -1 if shutting down, full, or out of memory. */
int  threadpool_add_work(struct ThreadPool* pool, work_func_t func, void* arg);

/* Block until the queue is empty and every worker idle. */
void threadpool_wait(struct ThreadPool* pool);

/* Stop and join the workers, then free the pool. */
void threadpool_destroy(struct ThreadPool* pool);

#endif /* THREAD_POOL_H */
