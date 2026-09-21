#ifndef CLIENT_REPLY_H
#define CLIENT_REPLY_H

#include "types.h"
#include "dns_wire.h"

/* Shaping of replies to our clients, shared by the UDP fast path, the UDP
 * worker and the TCP worker. */

/* Largest error reply: header + one question + OPT. */
#define ERROR_REPLY_MAX (HEADER_LEN + 260 + OPT_RR_LEN)

/* Header + echoed question (stubs drop replies whose question doesn't match)
 * with `rcode`; OPT added for EDNS clients except on FORMERR.  Returns the
 * length, or 0 on bad input. */
int build_error_reply(const unsigned char* req, ssize_t req_len, int rcode,
                      unsigned char* out, int out_cap);

/* BADVERS for EDNS version > 0 (RFC 6891 §6.1.3). */
int build_badvers_reply(const unsigned char* req, ssize_t req_len, bool do_bit,
                        unsigned char* out, int out_cap);

void send_error_udp(int sock, const struct sockaddr* addr, socklen_t addr_len,
                    const unsigned char* req, ssize_t req_len, int rcode);

/* Allocation-free parse of a standard class-IN query: lowercased QNAME,
 * QTYPE, DO bit and EDNS UDP size (0 = no EDNS).  Returns 0 if the worker
 * should handle it instead. */
int quick_parse_query(const char* buf, ssize_t len, char* domain_out, int domain_max,
                      uint16_t* qtype_out, bool* do_out, uint16_t* edns_size_out);

/* Fit a reply to the client's UDP limit (min(EDNS size, ours); 512 without
 * EDNS): over it, TC=1 with only the question (+OPT).  EDNS clients always
 * get an OPT back (RFC 6891 §7).  May realloc *buf. */
void finalize_udp_truncation(char** buf, ssize_t* len, uint16_t edns_udp_size, bool do_bit);

/* Append our OPT if the reply has none.  May realloc *buf. */
void ensure_edns_opt(char** buf, ssize_t* len, bool do_bit);

/* Forwarded answer gets our flags: AA=0, RA=1, RD/CD echo the client
 * (RFC 1035 §4.1.1, RFC 4035 §3.2.2). */
void normalize_forwarded_flags(unsigned char* resp, ssize_t len, int client_rd, int client_cd);

/* Echo the client's QNAME bytes (0x20 mixed case) into the reply. */
void restore_question_case(unsigned char* resp, ssize_t resp_len,
                           const unsigned char* query, ssize_t query_len);

#endif /* CLIENT_REPLY_H */
