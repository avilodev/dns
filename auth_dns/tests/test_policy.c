/*
 * Unit tests for policy.c — pure decision engine, exercised through the real
 * file parser (a temp config fixture), no sockets.
 *
 * Build & run (from auth_dns/):
 *   gcc -Wall -Wextra -Isrc tests/test_policy.c src/policy.c src/dns_synth.c \
 *       -lpthread -o /tmp/test_policy && /tmp/test_policy
 */
#include "policy.h"
#include "types.h"      /* QTYPE_A / QTYPE_AAAA */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define QTYPE_MX 15

static int g_fail = 0, g_checks = 0;
#define CHECK(cond, msg) do {                                           \
    g_checks++;                                                         \
    if (!(cond)) { g_fail++; printf("  FAIL: %s\n", (msg)); }           \
} while (0)

static const char* CONFIG_PATH = "/tmp/test_auth_policy_config.txt";

/* A realistic config: [domain] zone sections (which policy.c must ignore) plus
 * the [blocklist] section it actually reads. */
static const char* CONFIG_FIXTURE =
    "# test config\n"
    "[avilo.com]\n"
    "A      192.168.1.2\n"
    "MX     10 mail.avilo.com\n"
    "\n"
    "[blocklist]\n"
    "0.0.0.0 tracker.net\n"
    "hulu.com\n"
    "child.parent.test\n"
    "0.0.0.0 m1.com m2.com\n"
    "UPPER.Example\n"
    "\n";

static void write_file(const char* path, const char* content)
{
    FILE* f = fopen(path, "w");
    if (!f) { printf("  FATAL: cannot write %s\n", path); return; }
    fputs(content, f);
    fclose(f);
}

static void test_subtree_and_asymmetry(void)
{
    printf("test_subtree_and_asymmetry\n");
    SynthAnswer a;
    CHECK(policy_lookup("hulu.com",       QTYPE_A, &a) == POLICY_BLOCK, "apex blocked");
    CHECK(policy_lookup("vortex.hulu.com", QTYPE_A, &a) == POLICY_BLOCK, "subdomain blocked");
    CHECK(policy_lookup("a.b.hulu.com",   QTYPE_A, &a) == POLICY_BLOCK, "deep subdomain blocked");
    CHECK(policy_lookup("nothulu.com",    QTYPE_A, &a) == POLICY_PASS,  "label-boundary: nothulu.com NOT blocked");
    CHECK(policy_lookup("hulu.com.evil.com", QTYPE_A, &a) == POLICY_PASS, "suffix-as-substring NOT blocked");
    CHECK(policy_lookup("child.parent.test",   QTYPE_A, &a) == POLICY_BLOCK, "child entry blocked");
    CHECK(policy_lookup("x.child.parent.test", QTYPE_A, &a) == POLICY_BLOCK, "below child blocked");
    CHECK(policy_lookup("parent.test",         QTYPE_A, &a) == POLICY_PASS,  "parent of a child entry NOT blocked");
}

static void test_parser_variants(void)
{
    printf("test_parser_variants\n");
    SynthAnswer a;
    CHECK(policy_lookup("tracker.net", QTYPE_A, &a) == POLICY_BLOCK, "hosts-format name blocked");
    CHECK(policy_lookup("m1.com",      QTYPE_A, &a) == POLICY_BLOCK, "multi-name line: m1");
    CHECK(policy_lookup("m2.com",      QTYPE_A, &a) == POLICY_BLOCK, "multi-name line: m2");
    CHECK(policy_lookup("UPPER.EXAMPLE", QTYPE_A, &a) == POLICY_BLOCK, "case-insensitive match");
    CHECK(policy_lookup("google.com",  QTYPE_A, &a) == POLICY_PASS,  "unlisted name passes");
}

static void test_zone_sections_ignored(void)
{
    printf("test_zone_sections_ignored\n");
    SynthAnswer a;
    /* Names that appear only in [domain] zone sections must NOT be blocked —
     * policy.c reads the [blocklist] section exclusively. */
    CHECK(policy_lookup("avilo.com",      QTYPE_A, &a) == POLICY_PASS, "zone apex not blocked");
    CHECK(policy_lookup("mail.avilo.com", QTYPE_A, &a) == POLICY_PASS, "zone MX target not blocked");
    CHECK(policy_lookup("192.168.1.2",    QTYPE_A, &a) == POLICY_PASS, "zone record value not blocked");
}

static void test_nxdomain_mode(void)
{
    printf("test_nxdomain_mode\n");
    policy_set_block_mode("nxdomain");
    CHECK(policy_block_mode_rcode() == 3, "block rcode == NXDOMAIN");
    SynthAnswer a;
    CHECK(policy_lookup("tracker.net", QTYPE_A, &a) == POLICY_BLOCK, "blocked");
    CHECK(a.addrlen == 0 && a.qtype == 0, "no answer record in NXDOMAIN mode");
}

static void test_blocked_counter(void)
{
    printf("test_blocked_counter\n");
    SynthAnswer a;
    uint64_t before = policy_blocked_count();
    policy_lookup("tracker.net", QTYPE_A, &a);  /* block */
    policy_lookup("hulu.com",    QTYPE_A, &a);  /* block */
    policy_lookup("google.com",  QTYPE_A, &a);  /* pass — must NOT count */
    CHECK(policy_blocked_count() - before == 2, "counter increments only on blocks");
}

static void test_sinkhole_zero(void)
{
    printf("test_sinkhole_zero\n");
    policy_set_block_mode("zero");
    CHECK(policy_block_mode_rcode() == 0, "sinkhole rcode == 0");
    SynthAnswer a;

    CHECK(policy_lookup("tracker.net", QTYPE_A, &a) == POLICY_BLOCK, "blocked A");
    CHECK(a.qtype == QTYPE_A && a.addrlen == 4 &&
          a.addr[0]==0 && a.addr[1]==0 && a.addr[2]==0 && a.addr[3]==0, "A = 0.0.0.0");

    CHECK(policy_lookup("tracker.net", QTYPE_AAAA, &a) == POLICY_BLOCK, "blocked AAAA");
    unsigned char zero6[16] = {0};
    CHECK(a.qtype == QTYPE_AAAA && a.addrlen == 16 && memcmp(a.addr, zero6, 16) == 0, "AAAA = ::");

    CHECK(policy_lookup("tracker.net", QTYPE_MX, &a) == POLICY_BLOCK, "blocked MX");
    CHECK(a.addrlen == 0 && a.qtype == 0, "MX sinkhole -> NODATA (no answer)");

    policy_set_block_mode("nxdomain");
}

static void test_sinkhole_ip(void)
{
    printf("test_sinkhole_ip\n");
    policy_set_block_mode("10.0.0.1");
    CHECK(policy_block_mode_rcode() == 0, "ip sinkhole rcode == 0");
    SynthAnswer a;
    CHECK(policy_lookup("tracker.net", QTYPE_A, &a) == POLICY_BLOCK, "blocked A");
    CHECK(a.addrlen == 4 && a.addr[0]==10 && a.addr[1]==0 && a.addr[2]==0 && a.addr[3]==1, "A = 10.0.0.1");
    CHECK(policy_lookup("tracker.net", QTYPE_AAAA, &a) == POLICY_BLOCK, "blocked AAAA");
    CHECK(a.addrlen == 0, "no v6 sink for a v4 ip -> NODATA");
    policy_set_block_mode("nxdomain");
}

static void test_empty_and_reload(void)
{
    printf("test_empty_and_reload\n");
    SynthAnswer a;
    CHECK(policy_load(NULL) >= 0, "load(NULL) ok");
    CHECK(policy_lookup("hulu.com", QTYPE_A, &a) == POLICY_PASS, "everything passes when empty");
    CHECK(policy_load(CONFIG_PATH) >= 0, "reload fixture ok");
    CHECK(policy_lookup("hulu.com", QTYPE_A, &a) == POLICY_BLOCK, "block active after reload");
}

int main(void)
{
    write_file(CONFIG_PATH, CONFIG_FIXTURE);

    if (policy_load(CONFIG_PATH) < 0) {
        printf("FATAL: policy_load failed\n");
        return 2;
    }
    policy_set_block_mode("nxdomain");

    test_subtree_and_asymmetry();
    test_parser_variants();
    test_zone_sections_ignored();
    test_nxdomain_mode();
    test_blocked_counter();
    test_sinkhole_zero();
    test_sinkhole_ip();
    test_empty_and_reload();

    printf("\n%d checks, %d failures\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
