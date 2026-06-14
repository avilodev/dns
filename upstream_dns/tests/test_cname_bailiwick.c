/*
 * Unit test: CNAME-answer bailiwick filtering (anti cache-poisoning).
 *
 * Regression test for the bug where the resolver trusted an out-of-bailiwick
 * A record that an authoritative server stapled onto a CNAME answer.
 *
 * Real-world trigger: destinyemblemcollector.com is hosted on Bluehost
 * (ns1/ns2.bluehost.com) and CNAMEs to a Heroku endpoint
 * (fast-romaine-...herokudns.com).  Bluehost is NOT authoritative for
 * herokudns.com, yet it answers the CNAME query with:
 *
 *     destinyemblemcollector.com.  CNAME  fast-romaine-...herokudns.com.
 *     fast-romaine-...herokudns.com.  A   74.220.199.6   (parking.bluehost.com)
 *
 * The A record is out-of-bailiwick and must be discarded so the CNAME target
 * is re-resolved against herokudns.com's real nameservers.  Public resolvers
 * (Cloudflare/Google/Quad9) do exactly that; this resolver used to trust the
 * stapled record and return the dead parking IP.
 *
 * Build & run (from upstream_dns/):
 *     gcc -Isrc -o /tmp/test_cname_bailiwick \
 *         tests/test_cname_bailiwick.c src/response_handler.c \
 *         src/utils.c src/dns_wire.c && /tmp/test_cname_bailiwick
 */
#include "response_handler.h"
#include "types.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* response_handler.c declares `extern Hints* g_hints[13];` (used only by
 * build_root_hints_response, which we don't call).  Provide the definition so
 * the standalone test links. */
Hints* g_hints[13] = {0};

static int g_failures = 0;

#define CHECK(cond, msg) do {                                            \
    if (cond) {                                                          \
        printf("  ok   - %s\n", (msg));                                  \
    } else {                                                             \
        printf("  FAIL - %s\n", (msg));                                  \
        g_failures++;                                                    \
    }                                                                    \
} while (0)

/* Write a presentation-form name (no trailing dot) as wire-format labels. */
static void put_name(unsigned char* b, size_t* pos, const char* name)
{
    const char* p = name;
    while (*p) {
        const char* dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        b[(*pos)++] = (unsigned char)len;
        memcpy(b + *pos, p, len);
        *pos += len;
        if (!dot) break;
        p = dot + 1;
    }
    b[(*pos)++] = 0; /* root label */
}

static void put_u16(unsigned char* b, size_t* pos, uint16_t v)
{
    b[(*pos)++] = (v >> 8) & 0xFF;
    b[(*pos)++] = v & 0xFF;
}

/*
 * Build a response packet.
 *   qname   - question / first owner name
 *   target  - CNAME target (NULL => no CNAME record)
 *   with_a  - append an A record owned by `target` (or `qname` if no target)
 * The A record's value is fixed (74.220.199.6); only its owner name matters
 * for the bailiwick check.
 */
static void build_response(struct Packet* resp, unsigned char* buf,
                           const char* qname, const char* target, int with_a)
{
    size_t pos = 0;

    /* Header */
    put_u16(buf, &pos, 0x1234);          /* id */
    put_u16(buf, &pos, 0x8400);          /* flags: QR=1, AA=1 */
    uint16_t ancount = (target ? 1 : 0) + (with_a ? 1 : 0);
    put_u16(buf, &pos, 1);               /* qdcount */
    put_u16(buf, &pos, ancount);         /* ancount */
    put_u16(buf, &pos, 0);               /* nscount */
    put_u16(buf, &pos, 0);               /* arcount */

    /* Question: qname A IN */
    put_name(buf, &pos, qname);
    put_u16(buf, &pos, QTYPE_A);
    put_u16(buf, &pos, 1);

    /* Answer 1: qname CNAME target */
    if (target) {
        put_name(buf, &pos, qname);
        put_u16(buf, &pos, QTYPE_CNAME);
        put_u16(buf, &pos, 1);                 /* class IN */
        put_u16(buf, &pos, 0); put_u16(buf, &pos, 300); /* ttl 300 */
        size_t rdlen_pos = pos; pos += 2;      /* rdlength placeholder */
        size_t rd_start = pos;
        put_name(buf, &pos, target);
        uint16_t rdlen = (uint16_t)(pos - rd_start);
        buf[rdlen_pos] = (rdlen >> 8) & 0xFF;
        buf[rdlen_pos + 1] = rdlen & 0xFF;
    }

    /* Answer 2: <target|qname> A 74.220.199.6 */
    if (with_a) {
        put_name(buf, &pos, target ? target : qname);
        put_u16(buf, &pos, QTYPE_A);
        put_u16(buf, &pos, 1);                 /* class IN */
        put_u16(buf, &pos, 0); put_u16(buf, &pos, 60);  /* ttl 60 */
        put_u16(buf, &pos, 4);                 /* rdlength */
        buf[pos++] = 74; buf[pos++] = 220; buf[pos++] = 199; buf[pos++] = 6;
    }

    memset(resp, 0, sizeof(*resp));
    resp->request = (char*)buf;
    resp->recv_len = (ssize_t)pos;
    resp->qdcount = 1;
    resp->ancount = ancount;
}

int main(void)
{
    unsigned char buf[512];
    struct Packet resp;

    printf("CNAME-answer bailiwick filtering\n");

    /* 1. The Bluehost bug: CNAME + out-of-bailiwick A. Must re-chase. */
    build_response(&resp, buf, "destinyemblemcollector.com",
                   "fast-romaine-d16t8phoreb9f9shy1a3fr8d.herokudns.com", 1);
    CHECK(cname_answer_needs_rechase(&resp, QTYPE_A, "destinyemblemcollector.com") == true,
          "out-of-bailiwick stapled A triggers re-chase");
    /* Documents the old classifier's blind spot: it sees an A of the right type
     * and calls the answer 'complete', ignoring whose name the A is for. */
    CHECK(is_cname_only_answer(&resp, QTYPE_A) == false,
          "is_cname_only_answer alone misclassifies the stapled answer as complete");

    /* 2. Legitimate same-authority CNAME+A (target under server's zone). Keep. */
    build_response(&resp, buf, "www.example.com", "web.example.com", 1);
    CHECK(cname_answer_needs_rechase(&resp, QTYPE_A, "example.com") == false,
          "in-bailiwick CNAME target with A is kept (no re-chase)");

    /* 3. Bare CNAME, no final A at all. Must re-chase (legacy behaviour). */
    build_response(&resp, buf, "www.example.com", "foo.example.net", 0);
    CHECK(cname_answer_needs_rechase(&resp, QTYPE_A, "example.com") == true,
          "bare CNAME (no final record) triggers re-chase");

    /* 4. Direct A answer, no CNAME. Never re-chase. */
    build_response(&resp, buf, "example.com", NULL, 1);
    CHECK(cname_answer_needs_rechase(&resp, QTYPE_A, "example.com") == false,
          "direct A answer with no CNAME is kept");

    /* 5. Root server-zone ("" / NULL): everything is in-bailiwick of the root,
     *    so a final record is trusted and we do NOT re-chase — preserves the
     *    prior fast-path behaviour and avoids spurious work. */
    build_response(&resp, buf, "destinyemblemcollector.com",
                   "fast-romaine-d16t8phoreb9f9shy1a3fr8d.herokudns.com", 1);
    CHECK(cname_answer_needs_rechase(&resp, QTYPE_A, "") == false,
          "root zone makes final record in-bailiwick (no re-chase)");
    CHECK(cname_answer_needs_rechase(&resp, QTYPE_A, NULL) == false,
          "NULL server_zone is treated as root (no re-chase)");

    printf("\n%s (%d failure%s)\n",
           g_failures == 0 ? "PASS" : "FAIL",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
