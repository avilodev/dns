#include "ns_resolver.h"
#include "dns_packet.h"
#include "resolve.h"
#include "response_handler.h"

#include <strings.h>

bool already_resolving_ns(const NSResolutionContext* ctx, const char* ns_name)
{
    if (!ctx || !ns_name) return false;
    for (int i = 0; i < ctx->count; i++)
        if (strcasecmp(ctx->ns_names[i], ns_name) == 0) return true;
    return false;
}

static char* resolve_in_context(const char* ns_name, uint16_t qtype, NSResolutionContext* ctx)
{
    if (ctx->depth >= MAX_NS_RESOLUTION_DEPTH || ctx->count >= MAX_NS_NAMES_TRACKED ||
        already_resolving_ns(ctx, ns_name))
        return NULL;

    struct Packet* query = build_query(ns_name, qtype, CLASS_IN);
    char* name = strdup(ns_name);
    if (!query || !name) {
        free_packet(query);
        free(name);
        return NULL;
    }

    /* Track the name while its resolution is on the stack. */
    ctx->ns_names[ctx->count++] = name;
    ctx->depth++;
    struct Packet* resp = send_resolver_with_ns_context(query, ctx);
    ctx->depth--;
    free(ctx->ns_names[--ctx->count]);
    free_packet(query);

    char* ip = resp && resp->ancount > 0 ? extract_ip_from_answer(resp, qtype) : NULL;
    free_packet(resp);
    return ip;
}

char* resolve_ns_addr(const char* ns_name, NSResolutionContext* ctx)
{
    if (!ns_name) return NULL;
    NSResolutionContext fresh = {0};
    if (!ctx) ctx = &fresh;
    char* ip = resolve_in_context(ns_name, QTYPE_A, ctx);
    if (!ip) ip = resolve_in_context(ns_name, QTYPE_AAAA, ctx);   /* IPv6-only NS */
    return ip;
}
