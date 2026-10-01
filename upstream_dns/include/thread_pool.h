#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <pthread.h>
#include <stdbool.h>

struct thread_pool;

typedef void* (*work_func_t)(void* arg);

struct thread_pool_config {
	int num_threads;
	int max_queue_size;     // 0 = unlimited
};

struct thread_pool* threadpool_create(struct thread_pool_config config);

// Queue work; -1 if shutting down, full, or out of memory
int  threadpool_add_work(struct thread_pool* pool, work_func_t func, void* arg);

// True when work is queued behind the busy workers (someone is waiting).
bool threadpool_has_waiting(struct thread_pool* pool);

// Block until the queue is empty and every worker idle.
void threadpool_wait(struct thread_pool* pool);

// Stop and join the workers, then free the pool.
void threadpool_destroy(struct thread_pool* pool);

#endif /* THREAD_POOL_H */
