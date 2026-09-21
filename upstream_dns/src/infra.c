#include "infra.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>   /* INET6_ADDRSTRLEN */

#define INFRA_SLOTS        4096
#define INFRA_UNKNOWN_MS   200      /* score of a never-queried server       */
#define INFRA_BACKOFF_MAX  120      /* seconds                               */
#define INFRA_BACKOFF_COST 100000   /* score penalty while backing off       */
#define INFRA_JITTER_MS    25       /* spread load across near-equal servers */

typedef struct {
    char     ip[INET6_ADDRSTRLEN];  /* "" = empty slot */
    int      srtt_ms;               /* smoothed RTT (EWMA, 1/8 gain)         */
    int      fails;                 /* consecutive failures                  */
    time_t   backoff_until;         /* monotonic seconds                     */
} InfraEntry;

static InfraEntry      g_infra[INFRA_SLOTS];
static pthread_mutex_t g_infra_lock = PTHREAD_MUTEX_INITIALIZER;

static time_t mono_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

static uint32_t ip_hash(const char* ip)
{
    uint32_t h = 2166136261u;
    for (; *ip; ip++) { h ^= (uint8_t)*ip; h *= 16777619u; }
    return h;
}

/* Slot for ip, claiming (overwriting) it when absent and `create` is set.
 * Direct-mapped: a collision simply replaces the older server's stats.
 * Caller holds g_infra_lock. */
static InfraEntry* infra_slot(const char* ip, bool create)
{
    InfraEntry* e = &g_infra[ip_hash(ip) % INFRA_SLOTS];
    if (strcmp(e->ip, ip) == 0) return e;
    if (!create) return NULL;
    memset(e, 0, sizeof(*e));
    snprintf(e->ip, sizeof(e->ip), "%s", ip);
    e->srtt_ms = INFRA_UNKNOWN_MS;
    return e;
}

void infra_report_rtt(const char* ip, int rtt_ms)
{
    if (!ip || !*ip) return;
    if (rtt_ms < 1) rtt_ms = 1;
    pthread_mutex_lock(&g_infra_lock);
    InfraEntry* e = infra_slot(ip, true);
    e->srtt_ms = e->fails == 0 && e->srtt_ms != INFRA_UNKNOWN_MS
               ? e->srtt_ms + (rtt_ms - e->srtt_ms) / 8
               : rtt_ms;                      /* first sample / recovery */
    e->fails = 0;
    e->backoff_until = 0;
    pthread_mutex_unlock(&g_infra_lock);
}

void infra_report_failure(const char* ip)
{
    if (!ip || !*ip) return;
    pthread_mutex_lock(&g_infra_lock);
    InfraEntry* e = infra_slot(ip, true);
    if (e->fails < 16) e->fails++;
    int backoff = 1 << (e->fails < 7 ? e->fails : 7);          /* 2..128 s */
    if (backoff > INFRA_BACKOFF_MAX) backoff = INFRA_BACKOFF_MAX;
    e->backoff_until = mono_now() + backoff;
    pthread_mutex_unlock(&g_infra_lock);
}

/* Per-thread xorshift for the jitter below: rand() is MT-safe only as a glibc
 * extension, and serialises every scoring call on one global lock. */
static int jitter_ms(void)
{
    static __thread uint32_t st = 0;
    if (st == 0) st = (uint32_t)(uintptr_t)&st ^ (uint32_t)mono_now() ^ 0x9E3779B9u;
    st ^= st << 13;
    st ^= st >> 17;
    st ^= st << 5;
    return (int)(st % INFRA_JITTER_MS);
}

int infra_score(const char* ip)
{
    if (!ip || !*ip) return INFRA_BACKOFF_COST;
    int score = INFRA_UNKNOWN_MS;
    pthread_mutex_lock(&g_infra_lock);
    InfraEntry* e = infra_slot(ip, false);
    if (e) {
        score = e->srtt_ms;
        if (e->backoff_until > mono_now()) score += INFRA_BACKOFF_COST;
    }
    pthread_mutex_unlock(&g_infra_lock);
    /* Small jitter so near-identical servers share the load. */
    return score + jitter_ms();
}
