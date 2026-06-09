/*
 * Unit tests for dns_synth_response() — pure wire construction, no I/O.
 * Self-contained: builds query fixtures with a local name encoder (dns_synth's
 * own encoder is internal/static), so it links only dns_synth.c.
 *
 * Build & run (from auth_dns/):
 *   gcc -Wall -Wextra -Isrc tests/test_dns_synth.c src/dns_synth.c \
 *       -o /tmp/test_dns_synth && /tmp/test_dns_synth
 */
#include "dns_synth.h"
#include "types.h"      /* QTYPE_A / QTYPE_AAAA / QTYPE_CNAME / RCODE_* / HEADER_LEN */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(cond, msg) do {                                           \
    g_checks++;                                                         \
    if (!(cond)) { g_fail++; printf("  FAIL: %s\n", (msg)); }           \
} while (0)

/* Local presentation-name -> wire-label encoder (for building fixtures and
 * computing expected CNAME rdata). Returns bytes written incl. terminator. */
static int t_encode_name(const char* name, unsigned char* out, size_t cap)
{
    size_t w = 0;
    if (name[0] == '\0') { if (cap < 1) return -1; out[w++] = 0; return (int)w; }
    const char* p = name;
    while (*p) {
        if (*p == '.') { p++; continue; }
        const char* e = p;
        while (*e && *e != '.') e++;
        size_t len = (size_t)(e - p);
        if (len > 63 || w + 1 + len + 1 > cap) return -1;
        out[w++] = (unsigned char)len;
        memcpy(out + w, p, len); w += len;
        p = e;
    }
    out[w++] = 0;
    return (int)w;
}

static ssize_t build_query(unsigned char* buf, size_t cap, const char* name,
                           uint16_t qtype, int rd, uint16_t id, int edns)
{
    if (cap < 12) return -1;
    memset(buf, 0, cap);
    buf[0] = (unsigned char)(id >> 8);
    buf[1] = (unsigned char)(id & 0xFF);
    buf[2] = rd ? 0x01 : 0x00;
    buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x01;       /* QDCOUNT = 1 */

    int pos = 12;
    int n = t_encode_name(name, buf + pos, cap - pos);
    if (n < 0) return -1;
    pos += n;
    if ((size_t)pos + 4 > cap) return -1;
    buf[pos++] = (unsigned char)(qtype >> 8);
    buf[pos++] = (unsigned char)(qtype & 0xFF);
    buf[pos++] = 0x00; buf[pos++] = 0x01;   /* QCLASS = IN */

    if (edns) {
        if ((size_t)pos + 11 > cap) return -1;
        buf[10] = 0x00; buf[11] = 0x01;      /* ARCOUNT = 1 */
        buf[pos++] = 0x00;
        buf[pos++] = 0x00; buf[pos++] = 0x29; /* OPT */
        buf[pos++] = 0x10; buf[pos++] = 0x00; /* UDP size 4096 */
        buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00;
        buf[pos++] = 0x00; buf[pos++] = 0x00; /* RDLEN = 0 */
    }
    return pos;
}

static int qname_len(const char* name)
{
    unsigned char tmp[256];
    return t_encode_name(name, tmp, sizeof(tmp));
}

static uint16_t rd16(const unsigned char* p) { return (uint16_t)((p[0] << 8) | p[1]); }

static void test_nxdomain_block(void)
{
    printf("test_nxdomain_block\n");
    unsigned char q[512], out[512];
    ssize_t qlen = build_query(q, sizeof(q), "ads.example.com", QTYPE_A, 1, 0xBEEF, 0);
    CHECK(qlen > 0, "build_query");

    int qend = 12 + qname_len("ads.example.com") + 4;
    ssize_t n = dns_synth_response(q, qlen, RCODE_NAME_ERROR, NULL, 0, out, sizeof(out));

    CHECK(n == qend, "NXDOMAIN length == header+question");
    CHECK(out[0] == 0xBE && out[1] == 0xEF, "txid echoed");
    CHECK((out[2] & 0x80) != 0, "QR set");
    CHECK((out[2] & 0x04) == 0, "AA clear");
    CHECK((out[2] & 0x01) == 1, "RD echoed (1)");
    CHECK((out[3] & 0x80) != 0, "RA set");
    CHECK((out[3] & 0x0F) == RCODE_NAME_ERROR, "RCODE == NXDOMAIN");
    CHECK(rd16(out + 4) == 1, "QDCOUNT == 1");
    CHECK(rd16(out + 6) == 0, "ANCOUNT == 0");
    CHECK(rd16(out + 10) == 0, "ARCOUNT == 0");
    CHECK(memcmp(out + 12, q + 12, qend - 12) == 0, "question echoed verbatim");
}

static void test_rd_not_set(void)
{
    printf("test_rd_not_set\n");
    unsigned char q[512], out[512];
    ssize_t qlen = build_query(q, sizeof(q), "x.test", QTYPE_A, 0, 0x0001, 0);
    CHECK(qlen > 0, "build_query");
    ssize_t n = dns_synth_response(q, qlen, RCODE_NAME_ERROR, NULL, 0, out, sizeof(out));
    CHECK(n > 0, "synth ok");
    CHECK((out[2] & 0x01) == 0, "RD echoed (0)");
}

static void test_edns_additional_dropped(void)
{
    printf("test_edns_additional_dropped\n");
    unsigned char q[512], out[512];
    ssize_t qlen = build_query(q, sizeof(q), "ads.example.com", QTYPE_A, 1, 0x1234, 1);
    CHECK(qlen > 0, "build_query w/ EDNS");
    int qend = 12 + qname_len("ads.example.com") + 4;
    ssize_t n = dns_synth_response(q, qlen, RCODE_NAME_ERROR, NULL, 0, out, sizeof(out));
    CHECK(n == qend, "OPT not echoed (len == question end)");
    CHECK(rd16(out + 10) == 0, "ARCOUNT == 0 despite query OPT");
}

static void test_local_a(void)
{
    printf("test_local_a\n");
    unsigned char q[512], out[512];
    ssize_t qlen = build_query(q, sizeof(q), "nas.lan", QTYPE_A, 1, 0x4242, 0);
    CHECK(qlen > 0, "build_query");
    int qend = 12 + qname_len("nas.lan") + 4;

    SynthAnswer a;
    memset(&a, 0, sizeof(a));
    a.qtype = QTYPE_A; a.addrlen = 4; a.ttl = 60;
    inet_pton(AF_INET, "192.168.1.10", a.addr);

    ssize_t n = dns_synth_response(q, qlen, RCODE_NO_ERROR, &a, 1, out, sizeof(out));
    CHECK(n == qend + 16, "A answer length (qend + 16)");
    CHECK(rd16(out + 6) == 1, "ANCOUNT == 1");

    const unsigned char* rr = out + qend;
    CHECK(rr[0] == 0xC0 && rr[1] == 0x0C, "owner compression pointer 0xC00C");
    CHECK(rd16(rr + 2) == QTYPE_A, "RR type A");
    CHECK(rd16(rr + 4) == 1, "RR class IN");
    CHECK(((uint32_t)rr[6] << 24 | rr[7] << 16 | rr[8] << 8 | rr[9]) == 60, "RR ttl 60");
    CHECK(rd16(rr + 10) == 4, "RDLENGTH 4");
    CHECK(rr[12] == 192 && rr[13] == 168 && rr[14] == 1 && rr[15] == 10, "rdata 192.168.1.10");
}

static void test_local_aaaa(void)
{
    printf("test_local_aaaa\n");
    unsigned char q[512], out[512];
    ssize_t qlen = build_query(q, sizeof(q), "nas.lan", QTYPE_AAAA, 1, 0x4243, 0);
    CHECK(qlen > 0, "build_query");
    int qend = 12 + qname_len("nas.lan") + 4;

    SynthAnswer a;
    memset(&a, 0, sizeof(a));
    a.qtype = QTYPE_AAAA; a.addrlen = 16; a.ttl = 120;
    inet_pton(AF_INET6, "fd00::1", a.addr);

    ssize_t n = dns_synth_response(q, qlen, RCODE_NO_ERROR, &a, 1, out, sizeof(out));
    CHECK(n == qend + 28, "AAAA answer length (qend + 28)");
    const unsigned char* rr = out + qend;
    CHECK(rd16(rr + 2) == QTYPE_AAAA, "RR type AAAA");
    CHECK(rd16(rr + 10) == 16, "RDLENGTH 16");
    unsigned char exp[16]; inet_pton(AF_INET6, "fd00::1", exp);
    CHECK(memcmp(rr + 12, exp, 16) == 0, "rdata fd00::1");
}

static void test_local_cname(void)
{
    printf("test_local_cname\n");
    unsigned char q[512], out[512];
    ssize_t qlen = build_query(q, sizeof(q), "dev.home", QTYPE_CNAME, 1, 0x4244, 0);
    CHECK(qlen > 0, "build_query");
    int qend = 12 + qname_len("dev.home") + 4;

    SynthAnswer a;
    memset(&a, 0, sizeof(a));
    a.qtype = QTYPE_CNAME; a.addrlen = 0; a.ttl = 30;
    strcpy(a.cname, "grafana.home");

    unsigned char enc[256];
    int enclen = t_encode_name("grafana.home", enc, sizeof(enc));

    ssize_t n = dns_synth_response(q, qlen, RCODE_NO_ERROR, &a, 1, out, sizeof(out));
    CHECK(n == qend + 12 + enclen, "CNAME answer length");
    const unsigned char* rr = out + qend;
    CHECK(rd16(rr + 2) == QTYPE_CNAME, "RR type CNAME");
    CHECK(rd16(rr + 10) == enclen, "RDLENGTH == encoded name len");
    CHECK(memcmp(rr + 12, enc, enclen) == 0, "rdata == encoded target");
}

static void test_rejects_bad_input(void)
{
    printf("test_rejects_bad_input\n");
    unsigned char q[512], out[512];

    CHECK(dns_synth_response((unsigned char*)"\x00", 1, 0, NULL, 0, out, sizeof(out)) == -1,
          "rejects short query");

    ssize_t qlen = build_query(q, sizeof(q), "a.b.c", QTYPE_A, 1, 1, 0);
    q[12] = 0xC0; q[13] = 0x05;
    CHECK(dns_synth_response(q, qlen, 0, NULL, 0, out, sizeof(out)) == -1,
          "rejects compression in question");

    qlen = build_query(q, sizeof(q), "ads.example.com", QTYPE_A, 1, 1, 0);
    CHECK(dns_synth_response(q, qlen, RCODE_NAME_ERROR, NULL, 0, out, 8) == -1,
          "rejects tiny out buffer");
}

int main(void)
{
    test_nxdomain_block();
    test_rd_not_set();
    test_edns_additional_dropped();
    test_local_a();
    test_local_aaaa();
    test_local_cname();
    test_rejects_bad_input();

    printf("\n%d checks, %d failures\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
