#include "thread_pool.h"

#include <stdio.h>
#include <stdlib.h>

struct WorkItem {
    work_func_t func;
    void* arg;
    struct WorkItem* next;
};

struct ThreadPool {
    pthread_t* threads;
    int num_threads;

    struct WorkItem* head;          /* FIFO work queue */
    struct WorkItem* tail;
    int queue_size;
    int max_queue_size;
    struct WorkItem* freelist;      /* recycled items: no malloc per enqueue */

    pthread_mutex_t lock;           /* guards everything above and below */
    pthread_cond_t  work_available;
    pthread_cond_t  work_done;

    bool shutdown;
    int  active_workers;
    int  completed_work;
    int  rejected_work;
};

static void free_items(struct WorkItem* item)
{
    while (item) {
        struct WorkItem* next = item->next;
        free(item);
        item = next;
    }
}

static void recycle_item(struct ThreadPool* pool, struct WorkItem* item)
{
    item->next = pool->freelist;
    pool->freelist = item;
}

static void* worker_thread(void* arg)
{
    struct ThreadPool* pool = arg;
    pthread_mutex_lock(&pool->lock);
    for (;;) {
        while (!pool->head && !pool->shutdown)
            pthread_cond_wait(&pool->work_available, &pool->lock);
        if (!pool->head) break;                         /* shutdown, queue drained */

        struct WorkItem* item = pool->head;
        pool->head = item->next;
        if (!pool->head) pool->tail = NULL;
        pool->queue_size--;
        pool->active_workers++;
        pthread_mutex_unlock(&pool->lock);

        item->func(item->arg);

        pthread_mutex_lock(&pool->lock);
        pool->active_workers--;
        pool->completed_work++;
        recycle_item(pool, item);
        pthread_cond_signal(&pool->work_done);
    }
    pthread_mutex_unlock(&pool->lock);
    return NULL;
}

/* Signal shutdown and join the first `started` workers. */
static void stop_workers(struct ThreadPool* pool, int started)
{
    pthread_mutex_lock(&pool->lock);
    pool->shutdown = true;
    pthread_cond_broadcast(&pool->work_available);
    pthread_mutex_unlock(&pool->lock);
    for (int i = 0; i < started; i++)
        pthread_join(pool->threads[i], NULL);
}

/* Queued args are not freed: their owners' layouts are unknown here (and
 * threadpool_wait() normally empties the queue first). */
static void free_pool(struct ThreadPool* pool)
{
    free_items(pool->head);
    free_items(pool->freelist);
    free(pool->threads);
    pthread_cond_destroy(&pool->work_done);
    pthread_cond_destroy(&pool->work_available);
    pthread_mutex_destroy(&pool->lock);
    free(pool);
}

struct ThreadPool* threadpool_create(struct ThreadPoolConfig config)
{
    if (config.num_threads <= 0) {
        fprintf(stderr, "Invalid thread count: %d\n", config.num_threads);
        return NULL;
    }
    struct ThreadPool* pool = calloc(1, sizeof(*pool));
    if (!pool) return NULL;
    pool->num_threads    = config.num_threads;
    pool->max_queue_size = config.max_queue_size;
    pthread_mutex_init(&pool->lock, NULL);
    pthread_cond_init(&pool->work_available, NULL);
    pthread_cond_init(&pool->work_done, NULL);

    /* Pre-allocate queue items (capped); more are malloc'd on demand. */
    int prealloc = config.max_queue_size > 0 && config.max_queue_size <= 1024
                 ? config.max_queue_size : 512;
    for (int i = 0; i < prealloc; i++) {
        struct WorkItem* wi = malloc(sizeof(*wi));
        if (!wi) break;
        recycle_item(pool, wi);
    }

    pool->threads = calloc((size_t)pool->num_threads, sizeof(pthread_t));
    if (!pool->threads) {
        free_pool(pool);
        return NULL;
    }
    for (int i = 0; i < pool->num_threads; i++) {
        if (pthread_create(&pool->threads[i], NULL, worker_thread, pool) != 0) {
            perror("Failed to create worker thread");
            stop_workers(pool, i);
            free_pool(pool);
            return NULL;
        }
    }
    printf("Thread pool created with %d worker threads\n", pool->num_threads);
    return pool;
}

int threadpool_add_work(struct ThreadPool* pool, work_func_t func, void* arg)
{
    if (!pool || !func) return -1;

    pthread_mutex_lock(&pool->lock);
    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->lock);
        return -1;
    }
    if (pool->max_queue_size > 0 && pool->queue_size >= pool->max_queue_size) {
        pool->rejected_work++;
        pthread_mutex_unlock(&pool->lock);
        fprintf(stderr, "Work queue full, rejecting work\n");
        return -1;
    }
    struct WorkItem* item = pool->freelist;
    if (item) pool->freelist = item->next;
    else if (!(item = malloc(sizeof(*item)))) {
        pthread_mutex_unlock(&pool->lock);
        return -1;
    }

    *item = (struct WorkItem){ func, arg, NULL };
    if (pool->tail) pool->tail->next = item;
    else            pool->head = item;
    pool->tail = item;
    pool->queue_size++;
    pthread_cond_signal(&pool->work_available);
    pthread_mutex_unlock(&pool->lock);
    return 0;
}

void threadpool_wait(struct ThreadPool* pool)
{
    if (!pool) return;
    pthread_mutex_lock(&pool->lock);
    while (pool->head || pool->active_workers > 0)
        pthread_cond_wait(&pool->work_done, &pool->lock);
    pthread_mutex_unlock(&pool->lock);
}

void threadpool_destroy(struct ThreadPool* pool)
{
    if (!pool) return;
    stop_workers(pool, pool->num_threads);
    printf("Thread pool destroyed. Completed: %d, Rejected: %d\n",
           pool->completed_work, pool->rejected_work);
    free_pool(pool);
}
