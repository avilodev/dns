#include "thread_pool.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct work_item {
	work_func_t func;
	void* arg;
	struct work_item* next;
};

struct thread_pool {
	pthread_t* threads;
	int num_threads;

	struct work_item* head;          // FIFO work queue
	struct work_item* tail;
	int queue_size;
	int max_queue_size;
	struct work_item* freelist;      // recycled items: no malloc per enqueue

	pthread_mutex_t lock;           // guards everything above and below
	pthread_cond_t  work_available;
	pthread_cond_t  work_done;

	bool shutdown;
	int  active_workers;
	unsigned long long completed_work;
	unsigned long long rejected_work;
	time_t last_full_warn;          // rate-limits the "queue full" warning
};

static void free_items(struct work_item* item)
{
	while(item) {
		struct work_item* next = item->next;
		free(item);
		item = next;
	}
}

static void recycle_item(struct thread_pool* pool, struct work_item* item)
{
	item->next = pool->freelist;
	pool->freelist = item;
}

static void* worker_thread(void* arg)
{
	struct thread_pool* pool = arg;

	pthread_mutex_lock(&pool->lock);

	for(;;) {
		while(!pool->head && !pool->shutdown)
			pthread_cond_wait(&pool->work_available, &pool->lock);
		if(!pool->head)
			break;                         // shutdown, queue drained

		struct work_item* item = pool->head;
		pool->head = item->next;
		if(!pool->head)
			pool->tail = NULL;
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

// Signal shutdown and join the first `started` workers.
static void stop_workers(struct thread_pool* pool, int started)
{
	pthread_mutex_lock(&pool->lock);
	pool->shutdown = true;
	pthread_cond_broadcast(&pool->work_available);
	pthread_mutex_unlock(&pool->lock);
	for(int i = 0; i < started; i++)
		pthread_join(pool->threads[i], NULL);
}

// Queued args are not freed: their owners' layouts are unknown here.
static void free_pool(struct thread_pool* pool)
{
	free_items(pool->head);
	free_items(pool->freelist);
	free(pool->threads);
	pthread_cond_destroy(&pool->work_done);
	pthread_cond_destroy(&pool->work_available);
	pthread_mutex_destroy(&pool->lock);
	free(pool);
}

struct thread_pool* threadpool_create(struct thread_pool_config config)
{
	if(config.num_threads <= 0) {
		fprintf(stderr, "Invalid thread count: %d\n", config.num_threads);
		return NULL;
	}
	struct thread_pool* pool = calloc(1, sizeof(*pool));
	if(!pool)
		return NULL;
	pool->num_threads    = config.num_threads;
	pool->max_queue_size = config.max_queue_size;
	pthread_mutex_init(&pool->lock, NULL);
	pthread_cond_init(&pool->work_available, NULL);
	pthread_cond_init(&pool->work_done, NULL);

	// Pre-allocate queue items (capped); more are malloc'd on demand.
	int prealloc = config.max_queue_size > 0 && config.max_queue_size <= 1024
				 ? config.max_queue_size : 512;
	for(int i = 0; i < prealloc; i++) {
		struct work_item* wi = malloc(sizeof(*wi));
		if(!wi)
			break;
		recycle_item(pool, wi);
	}

	pool->threads = calloc((size_t)pool->num_threads, sizeof(pthread_t));
	if(!pool->threads) {
		free_pool(pool);
		return NULL;
	}

	for(int i = 0; i < pool->num_threads; i++) {
		if(pthread_create(&pool->threads[i], NULL, worker_thread, pool) != 0) {
			perror("Failed to create worker thread");
			stop_workers(pool, i);
			free_pool(pool);
			return NULL;
		}
	}

	printf("Thread pool created with %d worker threads\n", pool->num_threads);

	return pool;
}

int threadpool_add_work(struct thread_pool* pool, work_func_t func, void* arg)
{
	if(!pool || !func)
		return -1;

	pthread_mutex_lock(&pool->lock);
	if(pool->shutdown) {
		pthread_mutex_unlock(&pool->lock);
		return -1;
	}

	if(pool->max_queue_size > 0 && pool->queue_size >= pool->max_queue_size) {
		pool->rejected_work++;
		// Once a minute at most: under overload this fires per query.
		time_t now = time(NULL);
		bool warn = now - pool->last_full_warn >= 60;
		unsigned long long rejected = pool->rejected_work;
		if(warn)
			pool->last_full_warn = now;
		pthread_mutex_unlock(&pool->lock);
		if(warn)
			fprintf(stderr, "Work queue full, rejecting work (%llu rejected so far)\n", rejected);
		return -1;
	}

	struct work_item* item = pool->freelist;
	if(item) {
		pool->freelist = item->next;
	} else if(!(item = malloc(sizeof(*item)))) {
		pthread_mutex_unlock(&pool->lock);
		return -1;
	}

	*item = (struct work_item){ func, arg, NULL };
	if(pool->tail)
		pool->tail->next = item;
	else
		pool->head = item;
	pool->tail = item;
	pool->queue_size++;
	pthread_cond_signal(&pool->work_available);
	pthread_mutex_unlock(&pool->lock);

	return 0;
}

bool threadpool_has_waiting(struct thread_pool* pool)
{
	if(!pool)
		return false;
	pthread_mutex_lock(&pool->lock);
	bool waiting = pool->head != NULL;
	pthread_mutex_unlock(&pool->lock);

	return waiting;
}

void threadpool_wait(struct thread_pool* pool)
{
	if(!pool)
		return;
	pthread_mutex_lock(&pool->lock);
	while(pool->head || pool->active_workers > 0)
		pthread_cond_wait(&pool->work_done, &pool->lock);
	pthread_mutex_unlock(&pool->lock);
}

void threadpool_destroy(struct thread_pool* pool)
{
	if(!pool)
		return;
	stop_workers(pool, pool->num_threads);
	printf("Thread pool destroyed. Completed: %llu, Rejected: %llu\n",
		   pool->completed_work, pool->rejected_work);
	free_pool(pool);
}
