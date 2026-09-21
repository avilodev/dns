#include "resolve.h"
#include "cache.h"
#include "cname_handler.h"
#include "config.h"
#include "dns_name.h"
#include "dns_packet.h"
#include "dnssec.h"
#include "dnssec_chain.h"
#include "infra.h"
#include "ns_resolver.h"
#include "response_handler.h"
#include "udp_client.h"

#include <limits.h>

/* ---- Helpers ----------------------------------------------------------- */

static void set_ad(struct Packet* p, bool on)
{
    if (p->request && p->recv_len >= 4) {
        uint16_t flags = rd16(p->request + 2);
        wr16(p->request + 2, on ? (flags | FLAG_AD) : (flags & ~FLAG_AD));
    }
    p->ad = on;
}

/* Never cache TC=1 answers (incomplete), nor — for a validating query — a
 * signed answer we could not validate (it would be served stale, non-AD). */
static bool cacheable_answer(struct Packet* response, bool want_dnssec)
{
    if (!response || !response->request || response->recv_len < 4 ||
        (rd16(response->request + 2) & FLAG_TC))
        return false;
    if (!want_dnssec || response->ad) return true;
    return !response_is_signed(response);
}

/*
 * Seed the chain with the root keys: fetch ". DNSKEY" and verify it against
 * the trust anchor only (never a key from the response).  Best-effort — on
 * failure validation just degrades to "unverifiable".
 */
static void bootstrap_root_keys(DnssecChainCtx* chain)
{
    char* root_ip = hints_random_root_ip();
    struct Packet* q = root_ip ? build_query(".", QTYPE_DNSKEY, CLASS_IN) : NULL;
    struct Packet* resp = q ? query_server(root_ip, q) : NULL;
    if (resp && resp->tc) {              /* the root DNSKEY RRset exceeds 1232 bytes */
        free_packet(resp);
        resp = query_server_tcp(root_ip, q);
    }
    if (resp) {
        if (dnssec_validate_root_dnskey(resp, g_trust_anchors) == 1)
            dnssec_chain_add_response_keys(chain, resp, ".");
        else
            fprintf(stderr, "DNSSEC: root DNSKEY did not validate against trust anchor\n");
    }
    free_packet(resp);
    free_packet(q);
    free(root_ip);
}

/*
 * The parent sent a DS for `zone`: fetch the zone's DNSKEYs from `ip`, promote
 * the KSK matching the DS, then the ZSKs it signs.  A DS that no key matches
 * marks the whole resolution bogus (RFC 4035 §5.5).
 */
static void fetch_zone_keys(DnssecChainCtx* chain, const char* ip, const char* zone)
{
    struct Packet* q = build_query(zone, QTYPE_DNSKEY, CLASS_IN);
    struct Packet* resp = q ? query_server(ip, q) : NULL;
    if (resp) {
        dnssec_chain_try_validate_dnskeys(chain, resp, zone);
        if (dnssec_validate_dnskey_with_chain(resp, zone, chain) == 1)
            dnssec_chain_add_response_keys(chain, resp, zone);
        if (!resp->tc && dnssec_chain_zone_bogus(chain, zone))
            chain->bogus = true;
    }
    free_packet(resp);
    free_packet(q);
}

/* ---- Nameserver candidates -------------------------------------------- */

/* Next usable server from a referral: glue first, else resolve the NS name
 * (within the NXNS budget).  malloc'd IP, or NULL when exhausted. */
static char* next_ns_candidate(NSCandidateList* list, int* idx, NSResolutionContext* ns_ctx)
{
    while (list && *idx < list->count) {
        NSCandidate* c = &list->candidates[(*idx)++];
        if (c->ns_ip) return strdup(c->ns_ip);
        if (list->glueless_left <= 0) continue;
        list->glueless_left--;
        if (ns_ctx && already_resolving_ns(ns_ctx, c->ns_name)) {
            fprintf(stderr, "    NS resolution loop detected\n");
            continue;
        }
        char* ip = resolve_ns_addr(c->ns_name, ns_ctx);
        if (ip) return ip;
    }
    return NULL;
}

/* Glue servers by infra_score() (fast, healthy first), then glueless ones.
 * Stable insertion sort. */
static void order_ns_candidates(NSCandidateList* list)
{
    if (!list || list->count < 2) return;
    int n = list->count;
    int* score = malloc((size_t)n * sizeof(int));
    if (!score) return;
    for (int i = 0; i < n; i++)
        score[i] = list->candidates[i].ns_ip ? infra_score(list->candidates[i].ns_ip) : INT_MAX;
    for (int i = 1; i < n; i++) {
        NSCandidate c = list->candidates[i];
        int sc = score[i], j = i - 1;
        for (; j >= 0 && score[j] > sc; j--) {
            list->candidates[j + 1] = list->candidates[j];
            score[j + 1] = score[j];
        }
        list->candidates[j + 1] = c;
        score[j + 1] = sc;
    }
    free(score);
}

/* Candidate list from cached addresses (takes ownership of ips). */
static NSCandidateList* list_from_ips(char** ips, int n)
{
    NSCandidateList* list = calloc(1, sizeof(*list));
    if (!list || !(list->candidates = calloc((size_t)(n > 0 ? n : 1), sizeof(NSCandidate)))) {
        free(list);
        return NULL;
    }
    list->capacity = n;
    for (int i = 0; i < n; i++) {
        list->candidates[i].ns_name = strdup("");
        list->candidates[i].ns_ip   = ips[i];
        list->count++;
    }
    return list;
}

/* Cache the zone's delegation: the server that answered, then the other glue. */
static void commit_ns_set(const char* zone, const char* answered_ip,
                          const NSCandidateList* list, uint32_t ttl)
{
    char* ips[NS_SET_MAX];
    int n = 0;
    ips[n++] = (char*)answered_ip;
    for (int i = 0; list && i < list->count && n < NS_SET_MAX; i++)
        if (list->candidates[i].ns_ip) ips[n++] = list->candidates[i].ns_ip;
    ns_cache_put_set(g_ns_cache, zone, ips, n, ttl);
}

/* ---- The delegation walk ------------------------------------------------ */

typedef struct {
    struct Packet*       query;
    NSResolutionContext* ns_ctx;
    DnssecChainCtx*      chain;
    AnswerCache*         cache;         /* NULL for QCLASS ANY */
    bool                 want_dnssec;

    char*            server;            /* IP being asked */
    char*            zone;              /* zone `server` serves ("" = root) */
    bool             from_cache;        /* started from a cached delegation */
    NSCandidateList* ns_list;           /* latest referral: fallback servers */
    int              ns_idx;
    char*            pending_zone;      /* NS-cache key, committed once a server answers */
    uint32_t         pending_ttl;
    char*            visited[MAX_SERVERS_VISITED];   /* "server|zone" loop detection */
    int              nvisited;
    int              iteration;
} Walk;

typedef enum { STEP_CONTINUE, STEP_DONE } Step;

static void walk_forget_path(Walk* w)
{
    for (int i = 0; i < w->nvisited; i++) free(w->visited[i]);
    w->nvisited = 0;
    free_ns_candidate_list(w->ns_list);
    w->ns_list = NULL;
    w->ns_idx = 0;
    free(w->pending_zone);
    w->pending_zone = NULL;
}

static void walk_free(Walk* w)
{
    walk_forget_path(w);
    free(w->server);
    free(w->zone);
}

/* Start at the deepest cached zone enclosing the name, else at a root.
 * Validating queries skip the NS cache: the walk from the root is what
 * collects the DS chain.  A DS lives in the parent, so skip the own zone. */
static void walk_start(Walk* w)
{
    const struct Packet* q = w->query;
    if (!w->want_dnssec && g_ns_cache && strcmp(q->full_domain, ".") != 0) {
        const char* zone = q->q_type == QTYPE_DS ? dname_parent(q->full_domain) : q->full_domain;
        for (; zone && *zone; zone = dname_parent(zone)) {
            char* ips[NS_SET_MAX];
            int n = ns_cache_get_set(g_ns_cache, zone, ips);   /* best first */
            if (n == 0) continue;
            w->server  = ips[0];
            w->ns_list = list_from_ips(ips + 1, n - 1);     /* siblings = fallbacks */
            if (!w->ns_list) for (int i = 1; i < n; i++) free(ips[i]);
            w->zone = strdup(zone);
            w->from_cache = true;
            return;
        }
    }
    w->server = hints_random_root_ip();
    w->zone = strdup("");
}

/* The cached delegation went stale (every server failed): walk from a root. */
static bool restart_from_root(Walk* w)
{
    fprintf(stderr, "  Cached nameservers for %s failed; retrying from root hints\n",
            w->query->full_domain);
    walk_forget_path(w);
    free(w->server);
    free(w->zone);
    w->zone = strdup("");
    w->from_cache = false;
    w->iteration = 0;
    w->server = hints_random_root_ip();
    return w->server != NULL;
}

/* Move to the next server of the latest referral.  False when none is left. */
static bool try_next_server(Walk* w)
{
    free(w->server);
    w->server = next_ns_candidate(w->ns_list, &w->ns_idx, w->ns_ctx);
    return w->server != NULL;
}

static void cache_answer(const Walk* w, struct Packet* resp)
{
    if (w->cache && resp && resp->request && resp->recv_len > 0 &&
        cacheable_answer(resp, w->want_dnssec))
        answer_cache_put(w->cache, w->query->full_domain, w->query->q_type,
                         resp->request, resp->recv_len, extract_min_ttl_from_response(resp));
}

static struct Packet* resolve_internal(struct Packet* query, int cname_depth, CnameChain* chain,
                                       NSResolutionContext* ns_ctx, DnssecChainCtx* dnssec_chain);

/* Resolve the CNAME target and splice "qname CNAME target" in front of it. */
static struct Packet* chase_cname(Walk* w, struct Packet* resp, int depth, CnameChain* chain)
{
    const struct Packet* q = w->query;
    char* target = extract_cname_target(resp);
    uint32_t ttl = extract_min_ttl_from_response(resp);   /* 0 = "don't cache" */
    free_packet(resp);
    if (!target) {
        fprintf(stderr, "Failed to extract CNAME target\n");
        return NULL;
    }
    if (check_cname_loop(chain, target)) {
        fprintf(stderr, "CNAME loop detected at: %s\n", target);
        free(target);
        return NULL;
    }
    cname_chain_add(chain, target);

    struct Packet* next = build_query(target, q->q_type, q->q_class);
    struct Packet* final = NULL;
    if (next) {
        next->cd = q->cd;              /* same validation gate for the target */
        next->do_bit = q->do_bit;
        final = resolve_internal(next, depth + 1, chain, w->ns_ctx, w->chain);
        free_packet(next);
    }
    if (!final) {
        fprintf(stderr, "Failed to resolve CNAME target\n");
        free(target);
        return NULL;
    }
    struct Packet* complete = reconstruct_cname_response(q, target, ttl, final);
    free(target);
    cache_answer(w, complete);
    return complete;
}

/* A positive answer.  Returns the final response or NULL (SERVFAIL). */
static struct Packet* handle_answer(Walk* w, struct Packet* resp, int depth, CnameChain* chain)
{
    const struct Packet* q = w->query;
    if (q->q_type != QTYPE_CNAME) {
        /* Bare CNAME, or address records stapled on by a server with no
         * authority over them (RFC 2181 §5.4.1): re-resolve the target. */
        if (cname_answer_needs_rechase(resp, q->q_type, w->zone))
            return chase_cname(w, resp, depth, chain);

        /* Only a bad signature fails; unsigned/unverifiable passes without AD
         * (RFC 4035 §4.7).  CD=1 clients skip this via want_dnssec. */
        if (w->want_dnssec) {
            int dv = dnssec_validate_with_chain(resp, g_trust_anchors, w->chain);
            if (dv == 0) {
                fprintf(stderr, "DNSSEC: validation FAILED for %s — returning SERVFAIL\n",
                        q->full_domain);
                free_packet(resp);
                return NULL;
            }
            if (dv == 1) set_ad(resp, true);
        }
    }
    cache_answer(w, resp);
    return resp;
}

/* A delegation: check it moves down the tree, then descend. */
static Step follow_referral(Walk* w, struct Packet* resp)
{
    const struct Packet* q = w->query;

    /* The apex must contain the qname and sit strictly below the answering
     * server's zone — anything else is lame, upward, or a poisoning attempt. */
    char* apex = extract_zone_apex(resp);
    if (!apex || !apex[0] || !dname_is_subdomain(q->full_domain, apex) ||
        !dname_is_subdomain(apex, w->zone) || dname_is_subdomain(w->zone, apex)) {
        fprintf(stderr, "Rejecting out-of-bailiwick referral: apex='%s' server-zone='%s' query='%s'\n",
                apex ? apex : "(none)", w->zone, q->full_domain);
        free(apex);
        free_packet(resp);
        infra_report_failure(w->server);
        return try_next_server(w) ? STEP_CONTINUE : STEP_DONE;
    }

    /* Glue is filtered to the answering server's zone: root vouches for
     * *.gtld-servers.net, a TLD for names under it, and so on. */
    NSCandidateList* list = extract_all_ns_with_glue(resp, w->zone);
    order_ns_candidates(list);
    int idx = 0;
    char* next = next_ns_candidate(list, &idx, w->ns_ctx);
    if (!next) {
        fprintf(stderr, "All nameservers failed or unreachable\n");
        free_ns_candidate_list(list);
        free(apex);
        free_packet(resp);
        return STEP_DONE;
    }

    free_ns_candidate_list(w->ns_list);
    w->ns_list = list;
    w->ns_idx = idx;
    free(w->zone);
    w->zone = apex;
    free(w->pending_zone);
    w->pending_zone = strdup(apex);
    w->pending_ttl = extract_referral_ns_ttl(resp);

    /* Chain of trust: DS records are kept only from a referral whose own
     * RRSIGs verified; then fetch the child's DNSKEYs to match them. */
    if (w->want_dnssec && w->chain) {
        int validated = dnssec_validate_with_chain(resp, g_trust_anchors, w->chain);
        dnssec_chain_process_referral(w->chain, resp, validated);
        if (dnssec_chain_has_pending_ds(w->chain, apex))
            fetch_zone_keys(w->chain, next, apex);
    }

    free(w->server);
    w->server = next;
    free_packet(resp);
    return STEP_CONTINUE;
}

/* Ask the current server once and act on the reply.  *out is set on success. */
static Step walk_step(Walk* w, int depth, CnameChain* chain, struct Packet** out)
{
    const struct Packet* q = w->query;

    /* Out of time: SERVFAIL inside auth_dns's forward timeout. */
    if (resolver_deadline_exceeded()) {
        fprintf(stderr, "Resolution budget (%ds) exceeded for %s — SERVFAIL\n",
                RECURSION_BUDGET_SEC, q->full_domain);
        return STEP_DONE;
    }
    if (w->want_dnssec && w->chain && w->chain->bogus) {
        fprintf(stderr, "DNSSEC: BOGUS — broken secure delegation for %s, returning SERVFAIL\n",
                q->full_domain);
        return STEP_DONE;
    }

    /* A loop is the same server asked about the same zone twice (one server
     * legitimately serves a parent and child). */
    char key[INET6_ADDRSTRLEN + DNAME_TEXT_MAX + 2];
    snprintf(key, sizeof(key), "%s|%s", w->server, w->zone);
    for (int i = 0; i < w->nvisited; i++) {
        if (strcmp(w->visited[i], key) == 0) {
            fprintf(stderr, "Referral loop detected\n");
            return STEP_DONE;
        }
    }
    if (w->nvisited >= MAX_SERVERS_VISITED) {
        fprintf(stderr, "Error: Referral loop — visited server limit (%d) exceeded\n",
                MAX_SERVERS_VISITED);
        return STEP_DONE;
    }
    if ((w->visited[w->nvisited] = strdup(key))) w->nvisited++;

    struct Packet* resp = query_server(w->server, w->query);
    if (!resp) {
        fprintf(stderr, "No response from %s\n", w->server);
        if (try_next_server(w) || (w->from_cache && restart_from_root(w)))
            return STEP_CONTINUE;
        return STEP_DONE;
    }

    /* A cached server that errors was probably re-delegated away. */
    if (w->from_cache && (resp->rcode == RCODE_SERVER_FAILURE ||
                          resp->rcode == RCODE_NOTIMP || resp->rcode == RCODE_REFUSED)) {
        fprintf(stderr, "  Cached NS %s returned rcode=%u\n", w->server, resp->rcode);
        infra_report_failure(w->server);
        free_packet(resp);
        return try_next_server(w) || restart_from_root(w) ? STEP_CONTINUE : STEP_DONE;
    }

    /* The server answered: now its delegation may be cached — but only under
     * a zone that contains the qname, or it could hijack unrelated names. */
    if (g_ns_cache && w->pending_zone) {
        if (dname_is_subdomain(q->full_domain, w->pending_zone))
            commit_ns_set(w->pending_zone, w->server, w->ns_list, w->pending_ttl);
        else
            fprintf(stderr, "Refusing out-of-bailiwick NS-cache key '%s' for query '%s'\n",
                    w->pending_zone, q->full_domain);
        free(w->pending_zone);
        w->pending_zone = NULL;
    }
    w->from_cache = false;

    /* TC=1: refetch answers over TCP; a truncated referral is still usable. */
    bool is_referral = !resp->aa && resp->ancount == 0 && resp->nscount > 0;
    if (resp->tc && !is_referral) {
        fprintf(stderr, "Warning: Truncated UDP answer from %s for %s — retrying over TCP\n",
                w->server, q->full_domain);
        struct Packet* tcp = query_server_tcp(w->server, w->query);
        free_packet(resp);
        if (!tcp) {
            fprintf(stderr, "  TCP fallback failed for truncated answer — failing\n");
            return STEP_DONE;
        }
        resp = tcp;
    } else if (resp->tc) {
        fprintf(stderr, "Warning: Truncated referral (TC=1) from %s for %s — partial data\n",
                w->server, q->full_domain);
    }

    /* AD must reflect our validation only; the far end's OPT is hop-by-hop. */
    set_ad(resp, false);
    strip_opt_rr(&resp->request, &resp->recv_len);
    if (resp->request && resp->recv_len >= HEADER_LEN)
        resp->arcount = rd16(resp->request + 10);

    /* NXDOMAIN is final only from an authoritative server. */
    if (resp->rcode == RCODE_NAME_ERROR && resp->aa) {
        clamp_negative_soa_ttl(resp);
        cache_answer(w, resp);
        *out = resp;
        return STEP_DONE;
    }
    /* Any other error is usually one misconfigured peer: try its siblings. */
    if (resp->rcode != RCODE_NO_ERROR) {
        fprintf(stderr, "DNS error RCODE=%u from %s\n", resp->rcode, w->server);
        infra_report_failure(w->server);
        free_packet(resp);
        return try_next_server(w) ? STEP_CONTINUE : STEP_DONE;
    }
    if (resp->ancount > 0) {
        if (!answer_owned_by_question(resp)) {
            fprintf(stderr, "Answer from %s not owned by %s — trying sibling\n",
                    w->server, q->full_domain);
            free_packet(resp);
            return try_next_server(w) ? STEP_CONTINUE : STEP_DONE;
        }
        *out = handle_answer(w, resp, depth, chain);
        return STEP_DONE;
    }
    if (resp->aa) {                                     /* NODATA */
        clamp_negative_soa_ttl(resp);
        cache_answer(w, resp);
        *out = resp;
        return STEP_DONE;
    }
    if (resp->nscount > 0)
        return follow_referral(w, resp);

    fprintf(stderr, "Unexpected response format from %s\n", w->server);
    free_packet(resp);
    return try_next_server(w) ? STEP_CONTINUE : STEP_DONE;
}

static struct Packet* resolve_internal(struct Packet* query, int cname_depth, CnameChain* chain,
                                       NSResolutionContext* ns_ctx, DnssecChainCtx* dnssec_chain)
{
    if (cname_depth >= MAX_CNAME_DEPTH) {
        fprintf(stderr, "Maximum CNAME chain depth (%d) reached\n", MAX_CNAME_DEPTH);
        return NULL;
    }
    if (!query || !query->request || !query->full_domain) return NULL;

    /* Validate only for DO=1, CD=0 clients (RFC 4035 §3.2.2).  Upstream
     * queries always set DO, so cached entries still carry RRSIGs. */
    bool want_dnssec = g_trust_anchors && query->do_bit && !query->cd;

    /* Root NS is answered offline; other root types go to a root server. */
    if (strcmp(query->full_domain, ".") == 0 && query->q_type == QTYPE_NS)
        return build_root_hints_response(query);

    /* The answer cache holds class IN only. */
    AnswerCache* cache = query->q_class == CLASS_IN ? g_answer_cache : NULL;
    if (cache) {
        struct Packet* cached = answer_cache_get(cache, query->full_domain, query->q_type);
        /* A validating query must not get a signed-but-unvalidated entry
         * (e.g. cached for a non-DO client): re-resolve to validate it. */
        if (cached && !(want_dnssec && !cached->ad && response_is_signed(cached)))
            return cached;
        free_packet(cached);
    }

    /* Seed the root keys once per top-level resolution (a non-empty chain
     * means it's done; CNAME hops share the chain). */
    if (want_dnssec && cname_depth == 0 && dnssec_chain && !dnssec_chain->keys)
        bootstrap_root_keys(dnssec_chain);

    Walk w = { .query = query, .ns_ctx = ns_ctx, .chain = dnssec_chain,
               .cache = cache, .want_dnssec = want_dnssec, .pending_ttl = DEFAULT_NS_TTL };
    walk_start(&w);
    if (!w.server) {
        fprintf(stderr, "Failed to get root server\n");
        walk_free(&w);
        return NULL;
    }

    struct Packet* result = NULL;
    Step st = STEP_CONTINUE;
    while (st == STEP_CONTINUE && w.iteration++ < MAX_ITERATIONS)
        st = walk_step(&w, cname_depth, chain, &result);
    if (st == STEP_CONTINUE)
        fprintf(stderr, "Maximum iterations (%d) reached\n", MAX_ITERATIONS);

    walk_free(&w);
    return result;
}

/* Fresh CNAME/DNSSEC state per top-level resolution; the time budget is
 * shared with an enclosing resolution when nested (NS-name lookups). */
static struct Packet* resolve_top(struct Packet* query, NSResolutionContext* ns_ctx)
{
    CnameChain cname_chain = {0};
    DnssecChainCtx dnssec_chain;
    dnssec_chain_init(&dnssec_chain);

    resolver_deadline_begin(RECURSION_BUDGET_SEC);
    struct Packet* result = resolve_internal(query, 0, &cname_chain, ns_ctx, &dnssec_chain);
    resolver_deadline_end();

    free_cname_chain(&cname_chain);
    dnssec_chain_free(&dnssec_chain);
    return result;
}

struct Packet* send_resolver(struct Packet* query)
{
    return resolve_top(query, NULL);
}

struct Packet* send_resolver_with_ns_context(struct Packet* query, NSResolutionContext* ns_ctx)
{
    return resolve_top(query, ns_ctx);
}
