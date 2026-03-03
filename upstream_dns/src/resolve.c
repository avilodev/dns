#include "resolve.h"
#include "ns_resolution_context.h"
#include "ns_resolver.h"
#include "cache.h"
#include "udp_client.h"
#include "dnssec.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>


extern Hints* g_hints[13];
extern NSCache* g_ns_cache;
extern AnswerCache* g_answer_cache;
extern TrustAnchor* g_trust_anchors;
/* Defined in main.c — held as rdlock for the entire duration of resolution
 * to prevent g_ns_cache being destroyed under us during a SIGHUP swap. */
extern pthread_rwlock_t g_ns_cache_rwlock;

/**
 * Public entry point for DNS resolution
 * Holds g_ns_cache rdlock for the lifetime of the resolution call so the
 * SIGHUP handler cannot free the old cache while we are using it.
 */
struct Packet* send_resolver(struct Packet* query)
{
    CnameChain chain = {0};
    pthread_rwlock_rdlock(&g_ns_cache_rwlock);
    struct Packet* result = send_resolver_internal(query, 0, &chain, NULL);
    pthread_rwlock_unlock(&g_ns_cache_rwlock);
    free_cname_chain(&chain);
    return result;
}

/**
 * Public entry point with NS context (for NS resolution)
 */
struct Packet* send_resolver_with_ns_context(struct Packet* query,
                                             NSResolutionContext* ns_context)
{
    CnameChain chain = {0};
    pthread_rwlock_rdlock(&g_ns_cache_rwlock);
    struct Packet* result = send_resolver_internal(query, 0, &chain, ns_context);
    pthread_rwlock_unlock(&g_ns_cache_rwlock);
    free_cname_chain(&chain);
    return result;
}

/**
 * Internal resolver with CNAME and NS tracking
 */
struct Packet* send_resolver_internal(struct Packet* query, int cname_depth,
                                     CnameChain* chain,
                                     NSResolutionContext* ns_context)
{
    if (cname_depth >= MAX_CNAME_DEPTH) {
        fprintf(stderr, "Maximum CNAME chain depth (%d) reached\n", MAX_CNAME_DEPTH);
        return NULL;
    }

    if (!query || !query->request || !query->full_domain) {
        fprintf(stderr, "Invalid query packet\n");
        return NULL;
    }

    // Handle root domain queries
    if (strcmp(query->full_domain, ".") == 0) {
        return build_root_hints_response(query);
    }

    // Check answer cache
    if (g_answer_cache) {
        struct Packet* cached = answer_cache_get(g_answer_cache, query->full_domain,
                                                query->q_type);
        if (cached) {
            return cached;
        }
    }

    // Find starting nameserver
    char* current_server_ip = NULL;
    bool started_from_cache = false;
    char* tld = get_tld_from_domain(query->full_domain);

    if (g_ns_cache) {
        current_server_ip = ns_cache_get(g_ns_cache, query->full_domain);
        if (current_server_ip) started_from_cache = true;
    }

    if (!current_server_ip && g_ns_cache && tld) {
        current_server_ip = ns_cache_get(g_ns_cache, tld);
        if (current_server_ip) started_from_cache = true;
    }

    if (!current_server_ip) {
        int server_idx = get_random_server();
        if (server_idx < 0 || server_idx >= 13 || !g_hints[server_idx] ||
            !g_hints[server_idx]->ipv4_record || !g_hints[server_idx]->ipv4_record->ip) {
            free(tld);
            fprintf(stderr, "Failed to get root server\n");
            return NULL;
        }

        current_server_ip = strdup(g_hints[server_idx]->ipv4_record->ip);
        if (!current_server_ip) {
            free(tld);
            return NULL;
        }
    }

    free(tld);

    // Resolution loop
    struct Packet* response = NULL;
    ServerHistory visited = {0};
    int iteration = 0;

    // NS fallback: keep the full candidate list from the most recent referral
    // so that if the chosen NS is unreachable we can try the others without
    // re-resolving from scratch.
    NSCandidateList* pending_ns_list = NULL;
    int pending_ns_idx = 0;

    // Deferred NS caching: record the zone apex at referral time but only
    // write the cache entry once query_server succeeds, so we never store an
    // unreachable IP in the NS cache.
    char* pending_cache_key = NULL;

// Free pending_ns_list and pending_cache_key without touching anything else.
#define RESOLVE_CLEANUP() do { \
    if (pending_ns_list) { free_ns_candidate_list(pending_ns_list); pending_ns_list = NULL; } \
    free(pending_cache_key); pending_cache_key = NULL; \
} while(0)

    while (iteration < MAX_ITERATIONS) {
        iteration++;

        // Check for server loop
        if (already_queried(&visited, current_server_ip)) {
            fprintf(stderr, "Referral loop detected\n");
            free(current_server_ip);
            free_server_history(&visited);
            RESOLVE_CLEANUP();
            return NULL;
        }

        // Add to visited servers
        if (visited.count < MAX_SERVERS_VISITED) {
            visited.servers[visited.count] = strdup(current_server_ip);
            if (visited.servers[visited.count]) {
                visited.count++;
            }
        } else {
            fprintf(stderr, "Error: Referral loop — visited server limit (%d) exceeded\n",
                    MAX_SERVERS_VISITED);
            free(current_server_ip);
            free_server_history(&visited);
            RESOLVE_CLEANUP();
            return NULL;
        }

        response = query_server(current_server_ip, query);

        if (!response) {
            fprintf(stderr, "✗ No response from %s\n", current_server_ip);
            free(current_server_ip);
            current_server_ip = NULL;

            // Try the next candidate from the most recent referral before giving up.
            while (pending_ns_list && pending_ns_idx < pending_ns_list->count) {
                int i = pending_ns_idx++;
                char* ns_name = pending_ns_list->candidates[i].ns_name;
                char* glue_ip  = pending_ns_list->candidates[i].ns_ip;
                char* fallback_ip = NULL;

                if (glue_ip) {
                    fallback_ip = strdup(glue_ip);
                } else {
                    if (ns_context && already_resolving_ns(ns_context, ns_name)) {
                        fprintf(stderr, "    NS resolution loop detected\n");
                        continue;
                    }
                    fallback_ip = ns_context
                        ? resolve_ns_name_internal(ns_name, QTYPE_A, ns_context)
                        : resolve_ns_name(ns_name, QTYPE_A);
                }

                if (fallback_ip) {
                    fprintf(stderr, "  → Trying fallback NS candidate: %s\n", fallback_ip);
                    current_server_ip = fallback_ip;
                    break;
                }
            }

            if (!current_server_ip) {
                // All candidates from the last referral are exhausted.
                // If the very first server came from the NS cache, treat it as
                // stale and retry the whole resolution from a fresh root hint.
                if (started_from_cache && iteration == 1) {
                    fprintf(stderr, "  Stale NS cache entry detected, retrying from root hints\n");
                    free_server_history(&visited);
                    memset(&visited, 0, sizeof(visited));
                    RESOLVE_CLEANUP();
                    started_from_cache = false;
                    iteration = 0;
                    int ridx = get_random_server();
                    if (ridx < 0 || ridx >= 13 || !g_hints[ridx] ||
                        !g_hints[ridx]->ipv4_record || !g_hints[ridx]->ipv4_record->ip) {
                        return NULL;
                    }
                    current_server_ip = strdup(g_hints[ridx]->ipv4_record->ip);
                    if (!current_server_ip) return NULL;
                } else {
                    free_server_history(&visited);
                    RESOLVE_CLEANUP();
                    return NULL;
                }
            }
            continue;
        }

        // query_server succeeded: commit the pending NS cache entry using the
        // IP that actually responded, then clear it.
        if (g_ns_cache && pending_cache_key) {
            ns_cache_put(g_ns_cache, pending_cache_key, current_server_ip, DEFAULT_NS_TTL);
            free(pending_cache_key);
            pending_cache_key = NULL;
        }

        // After the first successful query we no longer need the cache-fallback guard.
        started_from_cache = false;

        // Warn on truncated responses.  For answer responses the client will
        // see TC=1 and can retry over TCP.  For referrals we continue with
        // whatever NS/AR records were returned; resolution may still succeed if
        // glue or NS-name resolution provides a usable address.
        if (response->tc) {
            fprintf(stderr, "Warning: Truncated response (TC=1) from %s for %s"
                    " — partial data, NS resolution may fall back to name lookup\n",
                    current_server_ip,
                    query->full_domain ? query->full_domain : "?");
        }

        // Handle errors
        if (response->rcode == RCODE_NAME_ERROR) {
            if (g_answer_cache && response->request && response->recv_len > 0) {
                uint32_t ttl = extract_min_ttl_from_response(response);
                if (ttl == 0) ttl = 300;
                answer_cache_put(g_answer_cache, query->full_domain, query->q_type,
                               response->request, response->recv_len, ttl);
            }
            free(current_server_ip);
            free_server_history(&visited);
            RESOLVE_CLEANUP();
            return response;
        }

        if (response->rcode != RCODE_NO_ERROR) {
            fprintf(stderr, "DNS error RCODE=%u\n", response->rcode);
            free(current_server_ip);
            free_server_history(&visited);
            RESOLVE_CLEANUP();
            return response;
        }

        // Handle Answer (including CNAME)
        if (response->ancount > 0) {

            if (query->q_type == QTYPE_CNAME) {
                if (g_answer_cache && response->request && response->recv_len > 0) {
                    uint32_t ttl = extract_min_ttl_from_response(response);
                    if (ttl == 0) ttl = 300;
                    answer_cache_put(g_answer_cache, query->full_domain, query->q_type,
                                   response->request, response->recv_len, ttl);
                }
                free(current_server_ip);
                free_server_history(&visited);
                RESOLVE_CLEANUP();
                return response;
            }

            bool cname_only = is_cname_only_answer(response, query->q_type);

            if (cname_only) {
                // Handle CNAME resolution
                char* cname_target = extract_cname_target(response);
                if (!cname_target) {
                    fprintf(stderr, "Failed to extract CNAME target\n");
                    free(current_server_ip);
                    free_server_history(&visited);
                    free_packet(response);
                    RESOLVE_CLEANUP();
                    return NULL;
                }

                // Check for CNAME loops
                if (check_cname_loop(chain, cname_target)) {
                    fprintf(stderr, "CNAME loop detected at: %s\n", cname_target);
                    free(cname_target);
                    free(current_server_ip);
                    free_server_history(&visited);
                    free_packet(response);
                    RESOLVE_CLEANUP();
                    return NULL;
                }

                // Store CNAME data for THIS hop only
                CnameChainData chain_data = {0};
                chain_data.entries[0].name = strdup(query->full_domain);
                chain_data.entries[0].target = strdup(cname_target);
                chain_data.entries[0].ttl = extract_min_ttl_from_response(response);
                if (chain_data.entries[0].ttl == 0) {
                    chain_data.entries[0].ttl = 300;
                }
                chain_data.entries[0].rdata = NULL;
                chain_data.entries[0].rdata_len = 0;
                chain_data.count = 1;

                // Add to loop detector
                if (chain && chain->count < MAX_CNAME_DEPTH) {
                    chain->domains[chain->count] = strdup(cname_target);
                    if (chain->domains[chain->count]) {
                        chain->count++;
                    }
                }

                // Free CNAME-only response BEFORE recursing
                free_packet(response);
                response = NULL;

                // Create query for CNAME target WITHOUT allocating request buffer
                struct Packet cname_query = {0};
                cname_query.full_domain = strdup(cname_target);
                cname_query.q_type = query->q_type;
                cname_query.q_class = query->q_class;
                cname_query.qdcount = 1;
                cname_query.ancount = 0;
                cname_query.nscount = 0;
                cname_query.arcount = 0;
                // format_resolver() will allocate request buffer

                struct Packet* formatted = format_resolver(&cname_query);

                // Free only the domain string we allocated
                free(cname_query.full_domain);

                if (!formatted) {
                    free(cname_target);
                    free(current_server_ip);
                    free_server_history(&visited);
                    free_cname_chain_data(&chain_data);
                    RESOLVE_CLEANUP();
                    return NULL;
                }

                // Recursively resolve CNAME target (pass ns_context through)
                struct Packet* final_answer = send_resolver_internal(
                    formatted,
                    cname_depth + 1,
                    chain,
                    ns_context
                );

                free_packet(formatted);
                free(cname_target);
                free(current_server_ip);
                free_server_history(&visited);
                RESOLVE_CLEANUP();

                if (!final_answer) {
                    fprintf(stderr, "✗ Failed to resolve CNAME target\n");
                    free_cname_chain_data(&chain_data);
                    return NULL;
                }

                // Reconstruct complete response (even if final_answer is NODATA/NXDOMAIN)
                struct Packet* complete = reconstruct_cname_response(
                    query,
                    &chain_data,
                    final_answer
                );

                free_cname_chain_data(&chain_data);

                // Cache the complete response
                if (g_answer_cache && complete && complete->request && complete->recv_len > 0) {
                    uint32_t ttl = extract_min_ttl_from_response(complete);
                    if (ttl == 0) ttl = 300;
                    answer_cache_put(g_answer_cache, query->full_domain,
                                   query->q_type, complete->request,
                                   complete->recv_len, ttl);
                }

                return complete;
            }

            // Got complete answer

            // DNSSEC validation: only fail on explicit signature mismatch
            // (result 0).  Missing DNSKEY or unsigned zone (result -1) is
            // treated as "unverifiable" and allowed through per RFC 4035 §4.7
            // (validating resolver behaviour when CD bit is not set).
            if (g_trust_anchors) {
                int dv = dnssec_validate_response(response, g_trust_anchors);
                if (dv == 0) {
                    fprintf(stderr,
                            "DNSSEC: validation FAILED for %s — returning SERVFAIL\n",
                            query->full_domain ? query->full_domain : "?");
                    free_packet(response);
                    free(current_server_ip);
                    free_server_history(&visited);
                    RESOLVE_CLEANUP();
                    return NULL;
                }
                /* dv==1: all RRSIGs verified — set AD bit (RFC 4035 §3.2.3) */
                if (dv == 1 && response->request && response->recv_len >= 4) {
                    uint16_t hflags = ntohs(*(uint16_t*)(response->request + 2));
                    hflags |= (1u << 5);  /* AD bit */
                    *(uint16_t*)(response->request + 2) = htons(hflags);
                    response->ad = 1;
                }
            }

            if (g_answer_cache && response->request && response->recv_len > 0) {
                uint32_t ttl = extract_min_ttl_from_response(response);
                if (ttl == 0) ttl = 300;
                answer_cache_put(g_answer_cache, query->full_domain, query->q_type,
                               response->request, response->recv_len, ttl);
            }

            free(current_server_ip);
            free_server_history(&visited);
            RESOLVE_CLEANUP();
            return response;
        }

        // Handle NODATA
        if (response->aa && response->ancount == 0) {
            if (g_answer_cache && response->request && response->recv_len > 0) {
                uint32_t ttl = extract_min_ttl_from_response(response);
                if (ttl == 0) ttl = 300;
                answer_cache_put(g_answer_cache, query->full_domain, query->q_type,
                               response->request, response->recv_len, ttl);
            }

            free(current_server_ip);
            free_server_history(&visited);
            RESOLVE_CLEANUP();
            return response;
        }

        // Handle referrals
        if (response->nscount > 0) {
            // Free any leftover candidate list from a previous referral.
            if (pending_ns_list) {
                free_ns_candidate_list(pending_ns_list);
                pending_ns_list = NULL;
                pending_ns_idx = 0;
            }

            NSCandidateList* ns_list = extract_all_ns_with_glue(response);
            char* next_server_ip = NULL;
            int chosen_idx = -1;

            if (ns_list && ns_list->count > 0) {
                // Pick the first usable NS: glue IP preferred (no extra lookup),
                // then fall back to resolving the NS name.
                for (int i = 0; i < ns_list->count && !next_server_ip; i++) {
                    char* ns_name = ns_list->candidates[i].ns_name;
                    char* glue_ip = ns_list->candidates[i].ns_ip;

                    if (glue_ip) {
                        next_server_ip = strdup(glue_ip);
                        chosen_idx = i;
                    } else {
                        if (ns_context && already_resolving_ns(ns_context, ns_name)) {
                            fprintf(stderr, "    NS resolution loop detected\n");
                            continue;
                        }
                        char* resolved = ns_context
                            ? resolve_ns_name_internal(ns_name, QTYPE_A, ns_context)
                            : resolve_ns_name(ns_name, QTYPE_A);
                        if (resolved) {
                            next_server_ip = resolved;
                            chosen_idx = i;
                        }
                    }
                }
            }

            if (!next_server_ip) {
                fprintf(stderr, "✗ All nameservers failed or unreachable\n");
                if (ns_list) free_ns_candidate_list(ns_list);
                free(current_server_ip);
                free_server_history(&visited);
                free_packet(response);
                RESOLVE_CLEANUP();
                return NULL;
            }

            // Keep the full list alive: if next_server_ip turns out to be
            // unreachable, the !response path above will walk the remaining
            // candidates (pending_ns_idx .. ns_list->count-1) as fallbacks.
            pending_ns_list = ns_list;
            pending_ns_idx = chosen_idx + 1;

            // Defer NS caching: record the zone apex now, but only write the
            // cache entry once query_server confirms the IP actually responds.
            free(pending_cache_key);
            pending_cache_key = NULL;
            if (g_ns_cache) {
                char* zone_apex = extract_zone_apex(response);
                if (zone_apex && zone_apex[0]) {
                    pending_cache_key = zone_apex;   // transfer ownership
                } else {
                    free(zone_apex);
                    pending_cache_key = strdup(query->full_domain);
                }
            }

            free(current_server_ip);
            current_server_ip = next_server_ip;
            free_packet(response);
            response = NULL;
            continue;
        }

        fprintf(stderr, "Unexpected response format\n");
        free(current_server_ip);
        free_server_history(&visited);
        free_packet(response);
        RESOLVE_CLEANUP();
        return NULL;
    }

    fprintf(stderr, "Maximum iterations (%d) reached\n", MAX_ITERATIONS);
    free(current_server_ip);
    free_server_history(&visited);
    if (response) {
        free_packet(response);
    }
    RESOLVE_CLEANUP();
    return NULL;

#undef RESOLVE_CLEANUP
}

/**
 * Check if server was already queried (referral loop detection)
 */
bool already_queried(ServerHistory* history, const char* server)
{
    if (!history || !server || server[0] == '\0') return false;
    
    for (int i = 0; i < history->count; i++) {
        if (history->servers[i] && strcmp(history->servers[i], server) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * Free server history memory
 */
void free_server_history(ServerHistory* history)
{
    if (!history) return;

    for (int i = 0; i < history->count; i++) {
        if (history->servers[i]) {
            free(history->servers[i]);
            history->servers[i] = NULL;
        }
    }
    history->count = 0;
}