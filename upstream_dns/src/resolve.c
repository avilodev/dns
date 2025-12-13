#include "resolve.h"
#include "ns_resolution_context.h"
#include "ns_resolver.h"
#include "cache.h"
#include "udp_client.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>


extern Hints* g_hints[13];
extern NSCache* g_ns_cache;
extern AnswerCache* g_answer_cache;

/**
 * Public entry point for DNS resolution
 * Initializes CNAME chain and calls internal resolver
 */
struct Packet* send_resolver(struct Packet* query)
{
    CnameChain chain = {0};
    struct Packet* result = send_resolver_internal(query, 0, &chain, NULL);
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
    struct Packet* result = send_resolver_internal(query, 0, &chain, ns_context);
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
        fprintf(stderr, "✗ Maximum CNAME chain depth (%d) reached\n", MAX_CNAME_DEPTH);
        return NULL;
    }
    
    if (!query || !query->request || !query->full_domain) {
        fprintf(stderr, "✗ Invalid query packet\n");
        return NULL;
    }

    // Handle root domain queries
    if (strcmp(query->full_domain, ".") == 0) {
        printf("→ Root domain query, returning hints\n");
        return build_root_hints_response(query);
    }

    // Print resolution header
    if (cname_depth == 0) {
        printf("\n╔═══════════════════════════════════════════════════════════════╗\n");
        printf("║          ITERATIVE DNS RESOLUTION                             ║\n");
        printf("╚═══════════════════════════════════════════════════════════════╝\n");
    }
    printf("Query: %s (Type: %s/%u, CNAME depth: %d)\n", 
           query->full_domain, qtype_to_string(query->q_type), 
           query->q_type, cname_depth);

    // Check answer cache
    if (g_answer_cache) {
        struct Packet* cached = answer_cache_get(g_answer_cache, query->full_domain, 
                                                query->q_type);
        if (cached) {
            printf("✓ Cache HIT (Answer Cache)\n");
            return cached;
        }
    }

    // Find starting nameserver
    char* current_server_ip = NULL;
    char* tld = get_tld_from_domain(query->full_domain);
    
    if (g_ns_cache) {
        current_server_ip = ns_cache_get(g_ns_cache, query->full_domain);
        if (current_server_ip) {
            printf("✓ NS Cache HIT: %s -> %s\n", query->full_domain, current_server_ip);
        }
    }
    
    if (!current_server_ip && g_ns_cache && tld) {
        current_server_ip = ns_cache_get(g_ns_cache, tld);
        if (current_server_ip) {
            printf("✓ NS Cache HIT: %s -> %s\n", tld, current_server_ip);
        }
    }
    
    if (!current_server_ip) {
        int server_idx = get_random_server();
        if (server_idx < 0 || server_idx >= 13 || !g_hints[server_idx] ||
            !g_hints[server_idx]->ipv4_record || !g_hints[server_idx]->ipv4_record->ip) {
            free(tld);
            fprintf(stderr, "✗ Failed to get root server\n");
            return NULL;
        }

        current_server_ip = strdup(g_hints[server_idx]->ipv4_record->ip);
        if (!current_server_ip) {
            free(tld);
            return NULL;
        }
        printf("→ Starting from root server: %s\n", current_server_ip);
    }
    
    free(tld);

    // Resolution loop
    struct Packet* response = NULL;
    ServerHistory visited = {0};
    int iteration = 0;

    while (iteration < MAX_ITERATIONS) {
        iteration++;

        // Check for server loop
        if (already_queried(&visited, current_server_ip)) {
            fprintf(stderr, "✗ Referral loop detected\n");
            free(current_server_ip);
            free_server_history(&visited);
            return NULL;
        }

        // Add to visited servers
        if (visited.count < MAX_SERVERS_VISITED) {
            visited.servers[visited.count] = strdup(current_server_ip);
            if (visited.servers[visited.count]) {
                visited.count++;
            }
        }

        printf("\n[Iteration %d] Querying: %s\n", iteration, current_server_ip);

        response = query_server(current_server_ip, query);
        
        if (!response) {
            fprintf(stderr, "✗ No response from %s\n", current_server_ip);
            free(current_server_ip);
            free_server_history(&visited);
            return NULL;
        }

        printf("  Response: QD=%u AN=%u NS=%u AR=%u RCODE=%u AA=%u\n",
               response->qdcount, response->ancount, response->nscount, 
               response->arcount, response->rcode, response->aa);

        // Handle errors
        if (response->rcode == RCODE_NAME_ERROR) {
            printf("✓ NXDOMAIN - Domain does not exist\n");
            if (g_answer_cache && response->request && response->recv_len > 0) {
                uint32_t ttl = extract_min_ttl_from_response(response);
                if (ttl == 0) ttl = 300;
                answer_cache_put(g_answer_cache, query->full_domain, query->q_type,
                               response->request, response->recv_len, ttl);
            }
            free(current_server_ip);
            free_server_history(&visited);
            return response;
        }

        if (response->rcode != RCODE_NO_ERROR) {
            fprintf(stderr, "✗ DNS error RCODE=%u\n", response->rcode);
            free(current_server_ip);
            free_server_history(&visited);
            return response;
        }

        // Handle Answer (including CNAME)
        if (response->ancount > 0) {

            if (query->q_type == QTYPE_CNAME) {
                printf("✓ Got CNAME answer (explicit query, not following chain)\n");
                
                if (g_answer_cache && response->request && response->recv_len > 0) {
                    uint32_t ttl = extract_min_ttl_from_response(response);
                    if (ttl == 0) ttl = 300;
                    answer_cache_put(g_answer_cache, query->full_domain, query->q_type,
                                   response->request, response->recv_len, ttl);
                }
                
                free(current_server_ip);
                free_server_history(&visited);
                return response;
            }

            bool cname_only = is_cname_only_answer(response, query->q_type);
            
            printf("  [DEBUG] ancount=%u, cname_only=%d, q_type=%u, aa=%u\n", response->ancount, cname_only, query->q_type, response->aa);

            if (cname_only) {
                // Handle CNAME resolution
                char* cname_target = extract_cname_target(response);
                if (!cname_target) {
                    fprintf(stderr, "✗ Failed to extract CNAME target\n");
                    free(current_server_ip);
                    free_server_history(&visited);
                    free_packet(response);
                    return NULL;
                }
                
                printf("→ Following CNAME: %s -> %s (depth %d)\n", 
                       query->full_domain, cname_target, cname_depth);
                
                // Check for CNAME loops
                if (check_cname_loop(chain, cname_target)) {
                    fprintf(stderr, "✗ CNAME loop detected at: %s\n", cname_target);
                    free(cname_target);
                    free(current_server_ip);
                    free_server_history(&visited);
                    free_packet(response);
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
                
                printf("  ✓ Stored CNAME record #1: %s -> %s (TTL=%u)\n",
                       query->full_domain, cname_target, chain_data.entries[0].ttl);
                
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
                    return NULL;
                }
                
                // Recursively resolve CNAME target (pass ns_context through)
                struct Packet* final_answer = send_resolver_internal(
                    formatted, 
                    cname_depth + 1, 
                    chain,
                    ns_context  // Pass NS context through
                );
                
                free_packet(formatted);
                free(cname_target);
                free(current_server_ip);
                free_server_history(&visited);
                
                if (!final_answer) {
                    fprintf(stderr, "✗ Failed to resolve CNAME target\n");
                    free_cname_chain_data(&chain_data);
                    return NULL;
                }
                
                // If CNAME target returns NODATA or NXDOMAIN, still reconstruct with the CNAME
                if (final_answer->rcode == RCODE_NAME_ERROR) {
                    printf("  ℹ CNAME target does not exist (NXDOMAIN)\n");
                } else if (final_answer->aa && final_answer->ancount == 0) {
                    printf("  ℹ CNAME target exists but has no %s records (NODATA)\n",
                           qtype_to_string(query->q_type));
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
            printf("✓ Got %s answer (%u records)\n", 
                   response->aa ? "AUTHORITATIVE" : "non-authoritative", 
                   response->ancount);
            
            if (g_answer_cache && response->request && response->recv_len > 0) {
                uint32_t ttl = extract_min_ttl_from_response(response);
                if (ttl == 0) ttl = 300;
                answer_cache_put(g_answer_cache, query->full_domain, query->q_type,
                               response->request, response->recv_len, ttl);
            }
            
            free(current_server_ip);
            free_server_history(&visited);
            return response;
        }

        // Handle NODATA
        if (response->aa && response->ancount == 0) {
            printf("✓ NODATA - Domain exists, but no %s records\n", 
                   qtype_to_string(query->q_type));
            
            if (g_answer_cache && response->request && response->recv_len > 0) {
                uint32_t ttl = extract_min_ttl_from_response(response);
                if (ttl == 0) ttl = 300;
                answer_cache_put(g_answer_cache, query->full_domain, query->q_type,
                               response->request, response->recv_len, ttl);
            }
            
            free(current_server_ip);
            free_server_history(&visited);
            return response;
        }

        // Handle referrals
        if (response->nscount > 0) {
            printf("→ Referral received (%u NS records)\n", response->nscount);
            
            NSCandidateList* ns_list = extract_all_ns_with_glue(response);
            char* next_server_ip = NULL;
            
            if (ns_list && ns_list->count > 0) {
                bool use_parallel = false;
                if (query->top_level_domain) {
                    // Use parallel for known-slow TLDs
                    if (strcasecmp(query->top_level_domain, "edu") == 0 ||
                        strcasecmp(query->top_level_domain, "gov") == 0 ||
                        strcasecmp(query->top_level_domain, "mil") == 0) {
                        use_parallel = true;
                    }
                }
                
                // Parallel queries
                if (use_parallel && ns_list->count >= 2) {
                    printf("  Using PARALLEL strategy (%s TLD)\n", 
                           query->top_level_domain ? query->top_level_domain : "unknown");
                    
                    int num_parallel = (ns_list->count < MAX_PARALLEL_QUERIES) ? 
                                      ns_list->count : MAX_PARALLEL_QUERIES;
                    
                    // Try up to 3 servers with glue IPs
                    printf("  Querying %d servers with 1s timeout...\n", num_parallel);
                    
                    int queries_tried = 0;
                    for (int i = 0; i < ns_list->count && queries_tried < num_parallel && !next_server_ip; i++) {
                        if (ns_list->candidates[i].ns_ip) {
                            char* test_ip = ns_list->candidates[i].ns_ip;
                            printf("    Trying %s ... ", test_ip);
                            fflush(stdout);
                            
                            struct Packet* test_resp = 
                                query_server_with_timeout(test_ip, query, TIMEOUT_PARALLEL_FAST);
                            
                            if (test_resp) {
                                printf("✓\n");
                                next_server_ip = strdup(test_ip);
                                free_packet(test_resp);
                            } else {
                                printf("✗ timeout\n");
                            }
                            queries_tried++;
                        }
                    }
                }
                
                // Sequential queries with fallback (for normal domains or if parallel failed)
                if (!next_server_ip) {
                    if (use_parallel) {
                        printf("  Parallel queries failed, falling back to sequential\n");
                    } else {
                        printf("  Using SEQUENTIAL strategy\n");
                    }
                    
                    for (int i = 0; i < ns_list->count && !next_server_ip; i++) {
                        char* ns_name = ns_list->candidates[i].ns_name;
                        char* glue_ip = ns_list->candidates[i].ns_ip;
                        
                        printf("  Trying NS #%d: %s\n", i + 1, ns_name);
                        
                        if (glue_ip) {
                            printf("    Testing glue IP: %s ... ", glue_ip);
                            fflush(stdout);
                            
                            // Use 2-second timeout for sequential
                            struct Packet* test_resp = 
                                query_server_with_timeout(glue_ip, query, TIMEOUT_SEQUENTIAL);
                            
                            if (test_resp) {
                                printf("✓\n");
                                next_server_ip = strdup(glue_ip);
                                free_packet(test_resp);
                            } else {
                                printf("✗ timeout\n");
                            }
                        }
                        
                        // Resolve NS name if glue failed
                        if (!next_server_ip) {
                            printf("    Resolving NS name: %s\n", ns_name);
                            
                            if (ns_context && already_resolving_ns(ns_context, ns_name)) {
                                fprintf(stderr, "    ✗ NS resolution loop detected\n");
                                continue;
                            }
                            
                            if (ns_context) {
                                next_server_ip = resolve_ns_name_internal(ns_name, QTYPE_A, ns_context);
                            } else {
                                next_server_ip = resolve_ns_name(ns_name, QTYPE_A);
                            }
                            
                            if (next_server_ip) {
                                printf("    ✓ Resolved %s -> %s\n", ns_name, next_server_ip);
                            }
                        }
                    }
                }
                
                free_ns_candidate_list(ns_list);
            }
            
            if (!next_server_ip) {
                fprintf(stderr, "✗ All nameservers failed or unreachable\n");
                free(current_server_ip);
                free_server_history(&visited);
                free_packet(response);
                return NULL;
            }

            printf("  Next server: %s\n", next_server_ip);

            if (g_ns_cache && query->full_domain) {
                ns_cache_put(g_ns_cache, query->full_domain, next_server_ip, 
                            DEFAULT_NS_TTL);
            }
            
            free(current_server_ip);
            current_server_ip = next_server_ip;
            free_packet(response);
            response = NULL;
            continue;
        }

        fprintf(stderr, "✗ Unexpected response format\n");
        free(current_server_ip);
        free_server_history(&visited);
        free_packet(response);
        return NULL;
    }

    fprintf(stderr, "✗ Maximum iterations (%d) reached\n", MAX_ITERATIONS);
    free(current_server_ip);
    free_server_history(&visited);
    if (response) {
        free_packet(response);
    }
    return NULL;
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