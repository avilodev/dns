#include "thread_pool.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// Work queue node
struct work_item {
	work_func_t func;
	void* arg;
	struct work_item* next;
};

// Thread pool structure
struct thread_pool {
	pthread_t* threads;
	int num_threads;
	
	// Work queue
	struct work_item* work_queue_head;
	struct work_item* work_queue_tail;
	int queue_size;
	int max_queue_size;

	// Pre-allocated WorkItem free-list: eliminates malloc/free per enqueue.
	struct work_item* item_freelist;

	// Synchronization
	pthread_mutex_t queue_mutex;
	pthread_cond_t work_available;
	pthread_cond_t work_done;
	
	// State
	bool shutdown;
	int active_workers;
	
	// Statistics
	unsigned long long completed_work;
	unsigned long long rejected_work;
	time_t last_full_warn;   // rate-limits the "queue full" warning
};

// Worker thread main loop: run queued work items until shutdown
static void* worker_thread(void* arg) {
	struct thread_pool* pool = (struct thread_pool*)arg;

	while(1) {
		pthread_mutex_lock(&pool->queue_mutex);

		// Wait for work or shutdown signal
		while(pool->work_queue_head == NULL && !pool->shutdown)
			pthread_cond_wait(&pool->work_available, &pool->queue_mutex);

		// Check for shutdown
		if(pool->shutdown && pool->work_queue_head == NULL) {
			pthread_mutex_unlock(&pool->queue_mutex);
			break;
		}

		// Get work item from queue
		struct work_item* item = pool->work_queue_head;
		if(item) {
			pool->work_queue_head = item->next;
			if(pool->work_queue_tail == item)
				pool->work_queue_tail = NULL;
			pool->queue_size--;
			pool->active_workers++;
		}

		pthread_mutex_unlock(&pool->queue_mutex);

		// Execute work (outside of lock to allow other threads to run)
		if(item) {
			item->func(item->arg);

			// Return item to freelist instead of freeing; update stats.
			pthread_mutex_lock(&pool->queue_mutex);
			pool->active_workers--;
			pool->completed_work++;
			item->next = pool->item_freelist;
			pool->item_freelist = item;
			pthread_cond_signal(&pool->work_done);
			pthread_mutex_unlock(&pool->queue_mutex);
		}
	}

	return NULL;
}

// Free the pre-allocated WorkItem freelist (error paths and destroy).
static void free_item_freelist(struct thread_pool* pool) {
	struct work_item* item = pool->item_freelist;

	while(item) {
		struct work_item* next = item->next;
		free(item);
		item = next;
	}
	pool->item_freelist = NULL;
}

// Allocate and start a thread pool.
struct thread_pool* threadpool_create(struct thread_pool_config config) {
	if(config.num_threads <= 0) {
		fprintf(stderr, "Invalid thread count: %d\n", config.num_threads);
		return NULL;
	}

	struct thread_pool* pool = calloc(1, sizeof(struct thread_pool));
	if(!pool) {
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
	if(pthread_mutex_init(&pool->queue_mutex, NULL) != 0) {
		perror("Mutex init failed");
		free(pool);
		return NULL;
	}

	if(pthread_cond_init(&pool->work_available, NULL) != 0) {
		perror("Condition variable init failed");
		pthread_mutex_destroy(&pool->queue_mutex);
		free(pool);
		return NULL;
	}

	if(pthread_cond_init(&pool->work_done, NULL) != 0) {
		perror("Condition variable init failed");
		pthread_cond_destroy(&pool->work_available);
		pthread_mutex_destroy(&pool->queue_mutex);
		free(pool);
		return NULL;
	}

	// Pre-allocate WorkItems into the freelist.
	int prealloc = (config.max_queue_size > 0 && config.max_queue_size <= 1024)
				   ? config.max_queue_size : 512;
	for(int i = 0; i < prealloc; i++) {
		struct work_item* wi = malloc(sizeof(struct work_item));
		if(!wi)
			break;  // non-fatal: will fall back to malloc on demand
		wi->next = pool->item_freelist;
		pool->item_freelist = wi;
	}

	// Create worker threads
	pool->threads = calloc(pool->num_threads, sizeof(pthread_t));
	if(!pool->threads) {
		perror("Failed to allocate thread array");
		free_item_freelist(pool);
		pthread_cond_destroy(&pool->work_done);
		pthread_cond_destroy(&pool->work_available);
		pthread_mutex_destroy(&pool->queue_mutex);
		free(pool);
		return NULL;
	}

	for(int i = 0; i < pool->num_threads; i++) {
		if(pthread_create(&pool->threads[i], NULL, worker_thread, pool) != 0) {
			perror("Failed to create worker thread");
			pool->shutdown = true;
			pthread_cond_broadcast(&pool->work_available);

			// Wait for already created threads
			for(int j = 0; j < i; j++)
				pthread_join(pool->threads[j], NULL);

			free(pool->threads);
			free_item_freelist(pool);
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

// Enqueue a work item.
int threadpool_add_work(struct thread_pool* pool, work_func_t func, void* arg) {
	if(!pool || !func)
		return -1;

	pthread_mutex_lock(&pool->queue_mutex);

	// Pop a pre-allocated item from the freelist; fall back to malloc if empty.
	struct work_item* item = pool->item_freelist;
	if(item) {
		pool->item_freelist = item->next;
	} else {
		pthread_mutex_unlock(&pool->queue_mutex);
		item = malloc(sizeof(struct work_item));
		if(!item) {
			perror("Failed to allocate work item");
			return -1;
		}
		pthread_mutex_lock(&pool->queue_mutex);
	}

	item->func = func;
	item->arg = arg;
	item->next = NULL;

	// Check if shutting down
	if(pool->shutdown) {
		item->next = pool->item_freelist;
		pool->item_freelist = item;
		pthread_mutex_unlock(&pool->queue_mutex);
		return -1;
	}

	// Check queue size limit
	if(pool->max_queue_size > 0 && pool->queue_size >= pool->max_queue_size) {
		pool->rejected_work++;
		item->next = pool->item_freelist;
		pool->item_freelist = item;
		// Once a minute at most: under overload this fires per query.
		time_t now = time(NULL);
		bool warn = now - pool->last_full_warn >= 60;
		unsigned long long rejected = pool->rejected_work;
		if(warn)
			pool->last_full_warn = now;
		pthread_mutex_unlock(&pool->queue_mutex);
		if(warn)
			fprintf(stderr, "Work queue full, rejecting work (%llu rejected so far)\n", rejected);
		return -1;
	}

	// Add to queue
	if(pool->work_queue_tail)
		pool->work_queue_tail->next = item;
	else
		pool->work_queue_head = item;
	pool->work_queue_tail = item;
	pool->queue_size++;

	// Signal a worker thread
	pthread_cond_signal(&pool->work_available);
	pthread_mutex_unlock(&pool->queue_mutex);

	return 0;
}

// Block until the work queue is empty and all workers are idle.
void threadpool_wait(struct thread_pool* pool) {
	if(!pool)
		return;

	pthread_mutex_lock(&pool->queue_mutex);

	while(pool->work_queue_head != NULL || pool->active_workers > 0)
		pthread_cond_wait(&pool->work_done, &pool->queue_mutex);

	pthread_mutex_unlock(&pool->queue_mutex);
}

// Signal all workers to shut down, join them, and free all resources.
void threadpool_destroy(struct thread_pool* pool) {
	if(!pool)
		return;

	// Signal shutdown
	pthread_mutex_lock(&pool->queue_mutex);
	pool->shutdown = true;
	pthread_cond_broadcast(&pool->work_available);
	pthread_mutex_unlock(&pool->queue_mutex);

	// Wait for all threads to finish
	for(int i = 0; i < pool->num_threads; i++)
		pthread_join(pool->threads[i], NULL);

	// Free remaining work items.
	struct work_item* item = pool->work_queue_head;
	while(item) {
		struct work_item* next = item->next;
		free(item);
		item = next;
	}

	// Free the pre-allocated WorkItem freelist.
	free_item_freelist(pool);

	// Cleanup
	free(pool->threads);
	pthread_cond_destroy(&pool->work_done);
	pthread_cond_destroy(&pool->work_available);
	pthread_mutex_destroy(&pool->queue_mutex);

	printf("Thread pool destroyed. Completed: %llu, Rejected: %llu\n",
		   pool->completed_work, pool->rejected_work);

	free(pool);
}

// True when work is queued behind the busy workers (someone is waiting).
bool threadpool_has_waiting(struct thread_pool* pool) {
	if(!pool)
		return false;
	pthread_mutex_lock(&pool->queue_mutex);
	bool waiting = pool->work_queue_head != NULL;
	pthread_mutex_unlock(&pool->queue_mutex);

	return waiting;
}

// Thread-safe snapshot of pool statistics.
void threadpool_get_stats(struct thread_pool* pool, struct thread_pool_stats* stats) {
	if(!pool || !stats)
		return;

	pthread_mutex_lock(&pool->queue_mutex);
	stats->active_threads = pool->active_workers;
	stats->queued_work = pool->queue_size;
	stats->completed_work = pool->completed_work;
	stats->rejected_work = pool->rejected_work;
	pthread_mutex_unlock(&pool->queue_mutex);
}