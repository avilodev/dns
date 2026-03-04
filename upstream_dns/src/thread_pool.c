#include "thread_pool.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Work queue node
struct WorkItem {
    work_func_t func;
    void* arg;
    struct WorkItem* next;
};

// Thread pool structure
struct ThreadPool {
    pthread_t* threads;
    int num_threads;
    
    // Work queue
    struct WorkItem* work_queue_head;
    struct WorkItem* work_queue_tail;
    int queue_size;
    int max_queue_size;
    
    // Synchronization
    pthread_mutex_t queue_mutex;
    pthread_cond_t work_available;
    pthread_cond_t work_done;
    
    // State
    bool shutdown;
    int active_workers;
    
    // Statistics
    int completed_work;
    int rejected_work;
};

/*
 * Worker thread main loop — waits on the queue condition variable and
 * executes work items until pool->shutdown is set.
 */
static void* worker_thread(void* arg) {
    struct ThreadPool* pool = (struct ThreadPool*)arg;
    
    while (1) {
        pthread_mutex_lock(&pool->queue_mutex);
        
        // Wait for work or shutdown signal
        while (pool->work_queue_head == NULL && !pool->shutdown) {
            pthread_cond_wait(&pool->work_available, &pool->queue_mutex);
        }
        
        // Check for shutdown
        if (pool->shutdown && pool->work_queue_head == NULL) {
            pthread_mutex_unlock(&pool->queue_mutex);
            break;
        }
        
        // Get work item from queue
        struct WorkItem* item = pool->work_queue_head;
        if (item) {
            pool->work_queue_head = item->next;
            if (pool->work_queue_tail == item) {
                pool->work_queue_tail = NULL;
            }
            pool->queue_size--;
            pool->active_workers++;
        }
        
        pthread_mutex_unlock(&pool->queue_mutex);
        
        // Execute work (outside of lock to allow other threads to run)
        if (item) {
            item->func(item->arg);
            free(item);
            
            // Update statistics
            pthread_mutex_lock(&pool->queue_mutex);
            pool->active_workers--;
            pool->completed_work++;
            pthread_cond_signal(&pool->work_done);
            pthread_mutex_unlock(&pool->queue_mutex);
        }
    }
    
    return NULL;
}

/*
 * Allocate and start a thread pool.  Returns NULL on error.
 * config.max_queue_size = 0 means unlimited queue depth.
 * Caller must call threadpool_destroy() when done.
 */
struct ThreadPool* threadpool_create(struct ThreadPoolConfig config) {
    if (config.num_threads <= 0) {
        fprintf(stderr, "Invalid thread count: %d\n", config.num_threads);
        return NULL;
    }
    
    struct ThreadPool* pool = calloc(1, sizeof(struct ThreadPool));
    if (!pool) {
        perror("Failed to allocate thread pool");
        return NULL;
    }
    
    pool->num_threads = config.num_threads;
    pool->max_queue_size = config.max_queue_size;
    pool->shutdown = false;
    pool->active_workers = 0;
    pool->completed_work = 0;
    pool->rejected_work = 0;
    
    // Initialize synchronization primitives
    if (pthread_mutex_init(&pool->queue_mutex, NULL) != 0) {
        perror("Mutex init failed");
        free(pool);
        return NULL;
    }
    
    if (pthread_cond_init(&pool->work_available, NULL) != 0) {
        perror("Condition variable init failed");
        pthread_mutex_destroy(&pool->queue_mutex);
        free(pool);
        return NULL;
    }
    
    if (pthread_cond_init(&pool->work_done, NULL) != 0) {
        perror("Condition variable init failed");
        pthread_cond_destroy(&pool->work_available);
        pthread_mutex_destroy(&pool->queue_mutex);
        free(pool);
        return NULL;
    }
    
    // Create worker threads
    pool->threads = calloc(pool->num_threads, sizeof(pthread_t));
    if (!pool->threads) {
        perror("Failed to allocate thread array");
        pthread_cond_destroy(&pool->work_done);
        pthread_cond_destroy(&pool->work_available);
        pthread_mutex_destroy(&pool->queue_mutex);
        free(pool);
        return NULL;
    }
    
    for (int i = 0; i < pool->num_threads; i++) {
        if (pthread_create(&pool->threads[i], NULL, worker_thread, pool) != 0) {
            perror("Failed to create worker thread");
            pool->shutdown = true;
            pthread_cond_broadcast(&pool->work_available);
            
            // Wait for already created threads
            for (int j = 0; j < i; j++) {
                pthread_join(pool->threads[j], NULL);
            }
            
            free(pool->threads);
            pthread_cond_destroy(&pool->work_done);
            pthread_cond_destroy(&pool->work_available);
            pthread_mutex_destroy(&pool->queue_mutex);
            free(pool);
            return NULL;
        }
    }
    
    printf("Thread pool created with %d worker threads\n", pool->num_threads);
    return pool;
}

/*
 * Enqueue a work item.  Returns 0 on success, -1 if the pool is shut down,
 * the queue is full, or allocation fails.
 */
int threadpool_add_work(struct ThreadPool* pool, work_func_t func, void* arg) {
    if (!pool || !func) {
        return -1;
    }
    
    struct WorkItem* item = malloc(sizeof(struct WorkItem));
    if (!item) {
        perror("Failed to allocate work item");
        return -1;
    }
    
    item->func = func;
    item->arg = arg;
    item->next = NULL;
    
    pthread_mutex_lock(&pool->queue_mutex);
    
    // Check if shutting down
    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->queue_mutex);
        free(item);
        return -1;
    }
    
    // Check queue size limit
    if (pool->max_queue_size > 0 && pool->queue_size >= pool->max_queue_size) {
        pool->rejected_work++;
        pthread_mutex_unlock(&pool->queue_mutex);
        free(item);
        fprintf(stderr, "Work queue full, rejecting work\n");
        return -1;
    }
    
    // Add to queue
    if (pool->work_queue_tail) {
        pool->work_queue_tail->next = item;
    } else {
        pool->work_queue_head = item;
    }
    pool->work_queue_tail = item;
    pool->queue_size++;
    
    // Signal a worker thread
    pthread_cond_signal(&pool->work_available);
    pthread_mutex_unlock(&pool->queue_mutex);
    
    return 0;
}

/*
 * Block until the work queue is empty and all workers are idle.
 */
void threadpool_wait(struct ThreadPool* pool) {
    if (!pool) return;
    
    pthread_mutex_lock(&pool->queue_mutex);
    
    while (pool->work_queue_head != NULL || pool->active_workers > 0) {
        pthread_cond_wait(&pool->work_done, &pool->queue_mutex);
    }
    
    pthread_mutex_unlock(&pool->queue_mutex);
}

/*
 * Signal all workers to shut down, join them, and free all resources.
 * After this call the pool pointer is invalid.
 */
void threadpool_destroy(struct ThreadPool* pool) {
    if (!pool) return;
    
    // Signal shutdown
    pthread_mutex_lock(&pool->queue_mutex);
    pool->shutdown = true;
    pthread_cond_broadcast(&pool->work_available);
    pthread_mutex_unlock(&pool->queue_mutex);
    
    // Wait for all threads to finish
    for (int i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);
    }
    
    /* Free remaining work items.  DO NOT free item->arg — each arg is a
     * UDPQueryContext/TCPQueryContext whose sub-allocations we can't know.
     * threadpool_wait() is always called before destroy, draining the queue,
     * so this loop is dead code in practice. */
    struct WorkItem* item = pool->work_queue_head;
    while (item) {
        struct WorkItem* next = item->next;
        free(item);
        item = next;
    }
    
    // Cleanup
    free(pool->threads);
    pthread_cond_destroy(&pool->work_done);
    pthread_cond_destroy(&pool->work_available);
    pthread_mutex_destroy(&pool->queue_mutex);
    
    printf("Thread pool destroyed. Completed: %d, Rejected: %d\n",
           pool->completed_work, pool->rejected_work);
    
    free(pool);
}

/*
 * Thread-safe snapshot of pool statistics (active workers, queue depth,
 * completed and rejected task counts).
 */
void threadpool_get_stats(struct ThreadPool* pool, struct ThreadPoolStats* stats) {
    if (!pool || !stats) return;
    
    pthread_mutex_lock(&pool->queue_mutex);
    stats->active_threads = pool->active_workers;
    stats->queued_work = pool->queue_size;
    stats->completed_work = pool->completed_work;
    stats->rejected_work = pool->rejected_work;
    pthread_mutex_unlock(&pool->queue_mutex);
}