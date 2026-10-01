#include "diag.h"
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

static void set_ad(struct packet* p, bool on)
{
	if(p->request && p->recv_len >= 4) {
		uint16_t flags = rd16(p->request + 2);
		wr16(p->request + 2, on ? (flags | FLAG_AD) : (flags & ~FLAG_AD));
	}
	p->ad = on;
}

// no TC=1, and no signed-but-unvalidated answer for a validating query
static bool cacheable_answer(struct packet* response, bool want_dnssec)
{
	if(!response || !response->request || response->recv_len < 4 ||
	   (rd16(response->request + 2) & FLAG_TC))
		return false;
	if(!want_dnssec || response->ad)
		return true;

	return !response_is_signed(response);
}

// verified against the trust anchor only
static void bootstrap_root_keys(dnssec_chain_ctx* chain)
{
	char* root_ip = hints_random_root_ip();
	struct packet* q = root_ip ? build_query(".", QTYPE_DNSKEY, CLASS_IN) : NULL;
	struct packet* resp = q ? query_server(root_ip, q) : NULL;

	if(resp && resp->tc) {              // the root DNSKEY RRset exceeds 1232 bytes
		free_packet(resp);
		resp = query_server_tcp(root_ip, q);
	}

	if(resp) {
		if(dnssec_validate_root_dnskey(resp, g_trust_anchors) == 1)
			dnssec_chain_add_response_keys(chain, resp, ".");
		else
			fprintf(stderr, "DNSSEC: root DNSKEY did not validate against trust anchor\n");
	}

	free_packet(resp);
	free_packet(q);
	free(root_ip);
}

// KSK via the DS, then ZSKs. unmatched DS = bogus (RFC 4035 5.5)
static void fetch_zone_keys(dnssec_chain_ctx* chain, const char* ip, const char* zone)
{
	struct packet* q = build_query(zone, QTYPE_DNSKEY, CLASS_IN);
	struct packet* resp = q ? query_server(ip, q) : NULL;

	if(resp) {
		dnssec_chain_try_validate_dnskeys(chain, resp, zone);
		if(dnssec_validate_dnskey_with_chain(resp, zone, chain) == 1)
			dnssec_chain_add_response_keys(chain, resp, zone);
		if(!resp->tc && dnssec_chain_zone_bogus(chain, zone))
			chain->bogus = true;
	}

	free_packet(resp);
	free_packet(q);
}

// glue first, else resolve the NS name within the NXNS budget
static char* next_ns_candidate(ns_candidate_list* list, int* idx, ns_resolution_context* ns_ctx)
{
	while(list && *idx < list->count) {
		ns_candidate* c = &list->candidates[(*idx)++];
		if(c->ns_ip)
			return strdup(c->ns_ip);
		if(list->glueless_left <= 0)
			continue;
		list->glueless_left--;
		if(ns_ctx && already_resolving_ns(ns_ctx, c->ns_name)) {
			DIAG(DIAG_DEBUG, "    NS resolution loop detected\n");
			continue;
		}
		char* ip = resolve_ns_addr(c->ns_name, ns_ctx);
		if(ip)
			return ip;
	}

	return NULL;
}

// best infra_score first, glueless last. stable
static void order_ns_candidates(ns_candidate_list* list)
{
	if(!list || list->count < 2)
		return;
	int n = list->count;
	int* score = malloc((size_t)n * sizeof(int));
	if(!score)
		return;
	for(int i = 0; i < n; i++)
		score[i] = list->candidates[i].ns_ip ? infra_score(list->candidates[i].ns_ip) : INT_MAX;

	for(int i = 1; i < n; i++) {
		ns_candidate c = list->candidates[i];
		int sc = score[i], j = i - 1;
		for(; j >= 0 && score[j] > sc; j--) {
			list->candidates[j + 1] = list->candidates[j];
			score[j + 1] = score[j];
		}
		list->candidates[j + 1] = c;
		score[j + 1] = sc;
	}

	free(score);
}

// takes ownership of ips
static ns_candidate_list* list_from_ips(char** ips, int n)
{
	ns_candidate_list* list = calloc(1, sizeof(*list));

	if(!list || !(list->candidates = calloc((size_t)(n > 0 ? n : 1), sizeof(ns_candidate)))) {
		free(list);
		return NULL;
	}
	list->capacity = n;
	for(int i = 0; i < n; i++) {
		list->candidates[i].ns_name = strdup("");
		list->candidates[i].ns_ip   = ips[i];
		list->count++;
	}

	return list;
}

// answering server goes first
static void commit_ns_set(const char* zone, const char* answered_ip,
						  const ns_candidate_list* list, uint32_t ttl)
{
	char* ips[NS_SET_MAX];
	int n = 0;

	ips[n++] = (char*)answered_ip;
	for(int i = 0; list && i < list->count && n < NS_SET_MAX; i++)
		if(list->candidates[i].ns_ip)
			ips[n++] = list->candidates[i].ns_ip;
	ns_cache_put_set(g_ns_cache, zone, ips, n, ttl);
}

typedef struct {
	struct packet*       query;
	ns_resolution_context* ns_ctx;
	dnssec_chain_ctx*      chain;
	answer_cache*         cache;         // NULL for QCLASS ANY
	bool                 want_dnssec;

	char*            server;
	char*            zone;              // "" = root
	bool             from_cache;
	ns_candidate_list* ns_list;           // fallbacks from latest referral
	int              ns_idx;
	char*            pending_zone;      // committed once a server answers
	uint32_t         pending_ttl;
	char*            visited[MAX_SERVERS_VISITED];   // "server|zone"
	int              nvisited;
	int              iteration;
	int              root_retries;
} Walk;

// root step has no referral siblings to fall back on
#define ROOT_RETRIES 2

typedef enum { STEP_CONTINUE, STEP_DONE } Step;

static void walk_forget_path(Walk* w)
{
	for(int i = 0; i < w->nvisited; i++)
		free(w->visited[i]);
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

// deepest cached zone, else a root
static void walk_start(Walk* w)
{
	const struct packet* q = w->query;

	if(!w->want_dnssec && g_ns_cache && strcmp(q->full_domain, ".") != 0) {
		const char* zone = q->q_type == QTYPE_DS ? dname_parent(q->full_domain) : q->full_domain;
		for(; zone && *zone; zone = dname_parent(zone)) {
			char* ips[NS_SET_MAX];
			int n = ns_cache_get_set(g_ns_cache, zone, ips);   // best first
			if(n == 0)
				continue;
			w->server  = ips[0];
			w->ns_list = list_from_ips(ips + 1, n - 1);
			if(!w->ns_list)
				for(int i = 1; i < n; i++)
					free(ips[i]);
			w->zone = strdup(zone);
			w->from_cache = true;
			return;
		}
	}

	w->server = hints_random_root_ip();
	w->zone = strdup("");
}

// cached delegation went stale
static bool restart_from_root(Walk* w)
{
	DIAG(DIAG_DEBUG, "  Cached nameservers for %s failed; retrying from root hints\n",
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

static bool try_next_server(Walk* w)
{
	free(w->server);
	w->server = next_ns_candidate(w->ns_list, &w->ns_idx, w->ns_ctx);
	// still at root: failed root now scores worse so another one gets picked
	if(!w->server && !w->ns_list && w->zone && !w->zone[0] &&
	   w->root_retries < ROOT_RETRIES) {
		w->root_retries++;
		w->server = hints_random_root_ip();
	}

	return w->server != NULL;
}

static void cache_answer(const Walk* w, struct packet* resp)
{
	if(w->cache && resp && resp->request && resp->recv_len > 0 &&
	   cacheable_answer(resp, w->want_dnssec)) {
		answer_cache_put(w->cache, w->query->full_domain, w->query->q_type,
						 resp->request, resp->recv_len, extract_min_ttl_from_response(resp));
	}
}

static struct packet* resolve_internal(struct packet* query, int cname_depth, cname_chain* chain,
									   ns_resolution_context* ns_ctx, dnssec_chain_ctx* dnssec_chain);

// splices "qname CNAME target" in front of the target's answer
static struct packet* chase_cname(Walk* w, struct packet* resp, int depth, cname_chain* chain)
{
	const struct packet* q = w->query;
	char* target = extract_cname_target(resp);
	uint32_t ttl = extract_min_ttl_from_response(resp);   // 0 = "don't cache"

	free_packet(resp);
	if(!target) {
		DIAG(DIAG_DEBUG, "Failed to extract CNAME target\n");
		return NULL;
	}
	if(check_cname_loop(chain, target)) {
		DIAG(DIAG_DEBUG, "CNAME loop detected at: %s\n", target);
		free(target);
		return NULL;
	}
	cname_chain_add(chain, target);

	struct packet* next = build_query(target, q->q_type, q->q_class);
	struct packet* final = NULL;

	if(next) {
		next->cd = q->cd;
		next->do_bit = q->do_bit;
		final = resolve_internal(next, depth + 1, chain, w->ns_ctx, w->chain);
		free_packet(next);
	}

	if(!final) {
		DIAG(DIAG_DEBUG, "Failed to resolve CNAME target\n");
		free(target);
		return NULL;
	}
	struct packet* complete = reconstruct_cname_response(q, target, ttl, final);
	free(target);
	cache_answer(w, complete);

	return complete;
}

// NULL = SERVFAIL
static struct packet* handle_answer(Walk* w, struct packet* resp, int depth, cname_chain* chain)
{
	const struct packet* q = w->query;

	if(q->q_type != QTYPE_CNAME) {
		// bare CNAME, or out-of-authority records stapled on (RFC 2181 5.4.1)
		if(cname_answer_needs_rechase(resp, q->q_type, w->zone))
			return chase_cname(w, resp, depth, chain);

		// only a bad sig fails, unsigned passes without AD (RFC 4035 4.7)
		if(w->want_dnssec) {
			int dv = dnssec_validate_with_chain(resp, g_trust_anchors, w->chain);
			if(dv == 0) {
				fprintf(stderr, "DNSSEC: validation FAILED for %s — returning SERVFAIL\n",
						q->full_domain);
				free_packet(resp);
				return NULL;
			}

			if(dv == 1)
				set_ad(resp, true);
		}
	}

	cache_answer(w, resp);

	return resp;
}

static Step follow_referral(Walk* w, struct packet* resp)
{
	const struct packet* q = w->query;

	// apex must contain qname and sit strictly below the server's zone
	char* apex = extract_zone_apex(resp);

	if(!apex || !apex[0] || !dname_is_subdomain(q->full_domain, apex) ||
	   !dname_is_subdomain(apex, w->zone) || dname_is_subdomain(w->zone, apex)) {
		DIAG(DIAG_DEBUG, "Rejecting out-of-bailiwick referral: apex='%s' server-zone='%s' query='%s'\n",
				apex ? apex : "(none)", w->zone, q->full_domain);
		free(apex);
		free_packet(resp);
		infra_report_failure(w->server);
		return try_next_server(w) ? STEP_CONTINUE : STEP_DONE;
	}

	// glue filtered to the answering server's zone
	ns_candidate_list* list = extract_all_ns_with_glue(resp, w->zone);
	order_ns_candidates(list);
	int idx = 0;
	char* next = next_ns_candidate(list, &idx, w->ns_ctx);
	if(!next) {
		DIAG(DIAG_DEBUG, "All nameservers failed or unreachable\n");
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

	// DS only kept from a referral whose RRSIGs verified
	if(w->want_dnssec && w->chain) {
		int validated = dnssec_validate_with_chain(resp, g_trust_anchors, w->chain);
		dnssec_chain_process_referral(w->chain, resp, validated);
		if(dnssec_chain_has_pending_ds(w->chain, apex))
			fetch_zone_keys(w->chain, next, apex);
	}

	free(w->server);
	w->server = next;
	free_packet(resp);

	return STEP_CONTINUE;
}

static Step walk_step(Walk* w, int depth, cname_chain* chain, struct packet** out)
{
	const struct packet* q = w->query;

	// SERVFAIL before auth_dns's forward timeout hits
	if(resolver_deadline_exceeded()) {
		DIAG(DIAG_DEBUG, "Resolution budget (%ds) exceeded for %s — SERVFAIL\n",
				RECURSION_BUDGET_SEC, q->full_domain);
		return STEP_DONE;
	}
	if(w->want_dnssec && w->chain && w->chain->bogus) {
		fprintf(stderr, "DNSSEC: BOGUS — broken secure delegation for %s, returning SERVFAIL\n",
				q->full_domain);
		return STEP_DONE;
	}

	// loop = same server + same zone (one server may serve parent and child)
	char key[INET6_ADDRSTRLEN + DNAME_TEXT_MAX + 2];
	snprintf(key, sizeof(key), "%s|%s", w->server, w->zone);

	for(int i = 0; i < w->nvisited; i++) {
		if(strcmp(w->visited[i], key) == 0) {
			DIAG(DIAG_DEBUG, "Referral loop detected\n");
			return STEP_DONE;
		}
	}

	if(w->nvisited >= MAX_SERVERS_VISITED) {
		DIAG(DIAG_DEBUG, "Error: Referral loop — visited server limit (%d) exceeded\n",
				MAX_SERVERS_VISITED);
		return STEP_DONE;
	}
	if((w->visited[w->nvisited] = strdup(key)))
		w->nvisited++;

	struct packet* resp = query_server(w->server, w->query);
	if(!resp) {
		DIAG(DIAG_DEBUG, "No response from %s\n", w->server);
		if(try_next_server(w) || (w->from_cache && restart_from_root(w)))
			return STEP_CONTINUE;
		return STEP_DONE;
	}

	// cached server erroring was probably re-delegated away
	if(w->from_cache && (resp->rcode == RCODE_SERVER_FAILURE ||
						  resp->rcode == RCODE_NOTIMP || resp->rcode == RCODE_REFUSED)) {
		DIAG(DIAG_DEBUG, "  Cached NS %s returned rcode=%u\n", w->server, resp->rcode);
		infra_report_failure(w->server);
		free_packet(resp);
		return try_next_server(w) || restart_from_root(w) ? STEP_CONTINUE : STEP_DONE;
	}

	// commit the delegation only on a real answer
	if(g_ns_cache && w->pending_zone &&
	   (resp->rcode == RCODE_NO_ERROR || resp->rcode == RCODE_NAME_ERROR)) {
		if(dname_is_subdomain(q->full_domain, w->pending_zone)) {
			commit_ns_set(w->pending_zone, w->server, w->ns_list, w->pending_ttl);
		} else {
			DIAG(DIAG_DEBUG, "Refusing out-of-bailiwick NS-cache key '%s' for query '%s'\n",
					w->pending_zone, q->full_domain);
		}

		free(w->pending_zone);
		w->pending_zone = NULL;
	}

	w->from_cache = false;

	// truncated referral is still usable, answers get refetched over TCP
	bool is_referral = !resp->aa && resp->ancount == 0 && resp->nscount > 0;
	if(resp->tc && !is_referral) {
		DIAG(DIAG_DEBUG, "Warning: Truncated UDP answer from %s for %s — retrying over TCP\n",
				w->server, q->full_domain);
		struct packet* tcp = query_server_tcp(w->server, w->query);
		free_packet(resp);
		if(!tcp) {
			DIAG(DIAG_DEBUG, "  TCP fallback failed for truncated answer — failing\n");
			return STEP_DONE;
		}
		resp = tcp;
	} else if(resp->tc) {
		DIAG(DIAG_DEBUG, "Warning: Truncated referral (TC=1) from %s for %s — partial data\n",
				w->server, q->full_domain);
	}

	// AD is ours to set, OPT is hop-by-hop
	set_ad(resp, false);
	strip_opt_rr(&resp->request, &resp->recv_len);
	if(resp->request && resp->recv_len >= HEADER_LEN)
		resp->arcount = rd16(resp->request + 10);

	if(resp->rcode == RCODE_NAME_ERROR && resp->aa) {
		clamp_negative_soa_ttl(resp);
		cache_answer(w, resp);
		*out = resp;
		return STEP_DONE;
	}

	// usually one misconfigured peer, try siblings
	if(resp->rcode != RCODE_NO_ERROR) {
		DIAG(DIAG_DEBUG, "DNS error RCODE=%u from %s\n", resp->rcode, w->server);
		infra_report_failure(w->server);
		free_packet(resp);
		return try_next_server(w) ? STEP_CONTINUE : STEP_DONE;
	}

	if(resp->ancount > 0) {
		if(!answer_owned_by_question(resp)) {
			DIAG(DIAG_DEBUG, "Answer from %s not owned by %s — trying sibling\n",
					w->server, q->full_domain);
			free_packet(resp);
			return try_next_server(w) ? STEP_CONTINUE : STEP_DONE;
		}

		*out = handle_answer(w, resp, depth, chain);
		return STEP_DONE;
	}

	// NODATA needs an SOA, else a referral with a bogus AA looks empty
	if(resp->aa && (resp->nscount == 0 || authority_has_soa(resp))) {
		clamp_negative_soa_ttl(resp);
		cache_answer(w, resp);
		*out = resp;
		return STEP_DONE;
	}

	if(resp->nscount > 0)
		return follow_referral(w, resp);

	DIAG(DIAG_DEBUG, "Unexpected response format from %s\n", w->server);
	free_packet(resp);

	return try_next_server(w) ? STEP_CONTINUE : STEP_DONE;
}

static struct packet* resolve_internal(struct packet* query, int cname_depth, cname_chain* chain,
									   ns_resolution_context* ns_ctx, dnssec_chain_ctx* dnssec_chain)
{
	if(cname_depth >= MAX_CNAME_DEPTH) {
		DIAG(DIAG_DEBUG, "Maximum CNAME chain depth (%d) reached\n", MAX_CNAME_DEPTH);
		return NULL;
	}
	if(!query || !query->request || !query->full_domain)
		return NULL;

	// DO=1 CD=0 only. upstream always sets DO so cache keeps RRSIGs
	bool want_dnssec = g_trust_anchors && query->do_bit && !query->cd;

	if(strcmp(query->full_domain, ".") == 0 && query->q_type == QTYPE_NS)
		return build_root_hints_response(query);

	answer_cache* cache = query->q_class == CLASS_IN ? g_answer_cache : NULL;
	if(cache) {
		struct packet* cached = answer_cache_get(cache, query->full_domain, query->q_type);
		// signed-but-unvalidated entry: re-resolve so we can validate
		if(cached && !(want_dnssec && !cached->ad && response_is_signed(cached)))
			return cached;
		free_packet(cached);
	}

	// once per top-level resolution, CNAME hops share the chain
	if(want_dnssec && cname_depth == 0 && dnssec_chain && !dnssec_chain->keys)
		bootstrap_root_keys(dnssec_chain);

	Walk w = { .query = query, .ns_ctx = ns_ctx, .chain = dnssec_chain,
			   .cache = cache, .want_dnssec = want_dnssec, .pending_ttl = DEFAULT_NS_TTL };
	walk_start(&w);
	if(!w.server) {
		fprintf(stderr, "Failed to get root server\n");
		walk_free(&w);
		return NULL;
	}

	struct packet* result = NULL;
	Step st = STEP_CONTINUE;
	while(st == STEP_CONTINUE && w.iteration++ < MAX_ITERATIONS)
		st = walk_step(&w, cname_depth, chain, &result);
	if(st == STEP_CONTINUE)
		DIAG(DIAG_DEBUG, "Maximum iterations (%d) reached\n", MAX_ITERATIONS);

	walk_free(&w);

	return result;
}

// nested NS-name lookups share the outer time budget
static struct packet* resolve_top(struct packet* query, ns_resolution_context* ns_ctx)
{
	cname_chain cname_state = {0};
	dnssec_chain_ctx dnssec_chain;

	dnssec_chain_init(&dnssec_chain);

	resolver_deadline_begin(RECURSION_BUDGET_SEC);
	struct packet* result = resolve_internal(query, 0, &cname_state, ns_ctx, &dnssec_chain);
	resolver_deadline_end();

	free_cname_chain(&cname_state);
	dnssec_chain_free(&dnssec_chain);

	return result;
}

struct packet* send_resolver(struct packet* query)
{
	return resolve_top(query, NULL);
}

struct packet* send_resolver_with_ns_context(struct packet* query, ns_resolution_context* ns_ctx)
{
	return resolve_top(query, ns_ctx);
}
