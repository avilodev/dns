#include "dnssec_chain.h"
#include "dns_wire.h"
#include "dnssec_wire.h"

#include <strings.h>
#include <openssl/evp.h>

void dnssec_chain_init(dnssec_chain_ctx *ctx)
{
	if(ctx)
		*ctx = (dnssec_chain_ctx){0};
}

void dnssec_chain_free(dnssec_chain_ctx *ctx)
{
	if(!ctx)
		return;
	while(ctx->keys) {
		validated_key *next = ctx->keys->next;
		free_dnskey_rdata(&ctx->keys->dk);
		free(ctx->keys);
		ctx->keys = next;
	}

	while(ctx->pending_ds) {
		pending_ds_node *next = ctx->pending_ds->next;
		free_ds_rdata(&ctx->pending_ds->ds);
		free(ctx->pending_ds);
		ctx->pending_ds = next;
	}
}

static const validated_key *find_key(const dnssec_chain_ctx *ctx, const char *zone,
									uint16_t key_tag, uint8_t algorithm)
{
	for(const validated_key *vk = ctx->keys; vk; vk = vk->next)
		if(vk->key_tag == key_tag && vk->dk.algorithm == algorithm &&
		   strcasecmp(vk->zone, zone) == 0)
			return vk;

	return NULL;
}

static bool copy_dnskey(const dnskey_rdata *src, dnskey_rdata *dst)
{
	*dst = *src;
	dst->pubkey = malloc(src->pubkey_len ? src->pubkey_len : 1);
	if(!dst->pubkey)
		return false;
	memcpy(dst->pubkey, src->pubkey, src->pubkey_len);

	return true;
}

int dnssec_chain_find_key(const dnssec_chain_ctx *ctx, const char *zone,
						  uint16_t key_tag, uint8_t algorithm, dnskey_rdata *dk_out)
{
	if(!ctx || !zone || !dk_out)
		return 0;
	const validated_key *vk = find_key(ctx, zone, key_tag, algorithm);

	return vk && copy_dnskey(&vk->dk, dk_out);
}

// dupes ignored, -1 on alloc failure
static int add_key(dnssec_chain_ctx *ctx, const char *zone, const dnskey_rdata *dk, uint16_t key_tag)
{
	if(find_key(ctx, zone, key_tag, dk->algorithm))
		return 0;
	validated_key *vk = calloc(1, sizeof(*vk));
	if(!vk || !copy_dnskey(dk, &vk->dk)) {
		free(vk);
		return -1;
	}
	snprintf(vk->zone, sizeof(vk->zone), "%s", zone);
	vk->key_tag = key_tag;
	vk->next = ctx->keys;
	ctx->keys = vk;

	return 0;
}

// SHA-1/256/384 digest types; NULL otherwise.
static const EVP_MD *ds_digest(uint8_t type)
{
	switch (type) {
	case 1:  return EVP_sha1();
	case 2:  return EVP_sha256();
	case 4:  return EVP_sha384();
	default: return NULL;
	}
}

// digest = owner_wire_lc | DNSKEY rdata (RFC 4034 5.1.4).
static int verify_ds(const ds_rdata *ds, const dnskey_rdata *dk,
					 const uint8_t *owner_wire, int owner_len)
{
	if(ds->algorithm != dk->algorithm)
		return 0;
	const EVP_MD *md = ds_digest(ds->digest_type);
	if(!md) {
		fprintf(stderr, "DNSSEC chain: unsupported DS digest type %u\n", ds->digest_type);
		return -1;
	}

	int data_len = owner_len + 4 + dk->pubkey_len;
	uint8_t *data = malloc((size_t)data_len);
	if(!data)
		return -1;
	memcpy(data, owner_wire, (size_t)owner_len);
	wr16(data + owner_len, dk->flags);
	data[owner_len + 2] = dk->protocol;
	data[owner_len + 3] = dk->algorithm;
	memcpy(data + owner_len + 4, dk->pubkey, dk->pubkey_len);

	uint8_t digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;
	int ok = EVP_Digest(data, (size_t)data_len, digest, &dlen, md, NULL);
	free(data);
	if(!ok)
		return -1;

	return ds->digest_len == dlen && memcmp(digest, ds->digest, dlen) == 0;
}

// Trust dk if a pending DS for (zone, key_tag) matches it; drop those DS.
static void try_promote_dnskey(dnssec_chain_ctx *ctx, const char *zone, const dnskey_rdata *dk,
							   uint16_t key_tag, const uint8_t *owner_wire, int owner_len)
{
	for(pending_ds_node **pp = &ctx->pending_ds; *pp; ) {
		pending_ds_node *pd = *pp;
		if(pd->ds.key_tag != key_tag || strcasecmp(pd->zone, zone) != 0) {
			pp = &pd->next;
			continue;
		}
		int r = verify_ds(&pd->ds, dk, owner_wire, owner_len);

		if(r == 1) {
			add_key(ctx, zone, dk, key_tag);
			*pp = pd->next;
			free_ds_rdata(&pd->ds);
			free(pd);
			continue;
		}

		if(r == 0) {
			fprintf(stderr, "DNSSEC chain: DS digest mismatch for zone '%s' key_tag=%u alg=%u\n",
					zone, key_tag, dk->algorithm);
		}
		pp = &pd->next;
	}
}

static int canonical_owner(const uint8_t *buf, int len, const dns_rr *rr,
						   uint8_t wire[256], char zone[DNAME_TEXT_MAX])
{
	int n = expand_name_lc(buf, len, rr->owner, wire, 256);

	if(n < 0 || dname_from_wire(wire, n, 0, false, zone, DNAME_TEXT_MAX) < 0)
		return -1;

	return n;
}

static void store_ds(dnssec_chain_ctx *ctx, const char *zone, const uint8_t *rdata, int rdlen)
{
	ds_rdata ds;

	if(parse_ds_rdata(rdata, rdlen, &ds) != 0)
		return;

	for(pending_ds_node *p = ctx->pending_ds; p; p = p->next) {
		if(p->ds.key_tag == ds.key_tag && p->ds.algorithm == ds.algorithm &&
		   strcasecmp(p->zone, zone) == 0) {
			free_ds_rdata(&ds);
			return;
		}
	}

	pending_ds_node *pd = calloc(1, sizeof(*pd));
	if(!pd) {
		free_ds_rdata(&ds);
		return;
	}
	snprintf(pd->zone, sizeof(pd->zone), "%s", zone);
	pd->ds = ds;
	pd->next = ctx->pending_ds;
	ctx->pending_ds = pd;
}

void dnssec_chain_process_referral(dnssec_chain_ctx *ctx, const struct packet *referral,
								   int referral_validated)
{
	if(!ctx || !referral || !referral->request || referral->recv_len < HEADER_LEN)
		return;
	const uint8_t *buf = (const uint8_t *)referral->request;
	int len = (int)referral->recv_len;
	uint8_t owner[256];
	char zone[DNAME_TEXT_MAX];
	rr_iter it; dns_rr rr;

	// Two passes so a DS and its DNSKEY in the same packet pair up in any order.
	if(referral_validated == 1)
		for(rr_iter_init(&it, buf, len); rr_next(&it, &rr); )
			if(rr.type == QTYPE_DS && canonical_owner(buf, len, &rr, owner, zone) >= 0)
				store_ds(ctx, zone, buf + rr.rdata, rr.rdlen);

	// matching an older stored DS is fine, the digest is the check
	for(rr_iter_init(&it, buf, len); rr_next(&it, &rr); ) {
		if(rr.type != QTYPE_DNSKEY)
			continue;
		int owner_len = canonical_owner(buf, len, &rr, owner, zone);
		dnskey_rdata dk;
		if(owner_len < 0 || parse_dnskey_rdata(buf + rr.rdata, rr.rdlen, &dk) != 0)
			continue;
		uint16_t tag = compute_key_tag(dk.flags, dk.protocol, dk.algorithm, dk.pubkey, dk.pubkey_len);
		try_promote_dnskey(ctx, zone, &dk, tag, owner, owner_len);
		free_dnskey_rdata(&dk);
	}
}

bool dnssec_chain_has_pending_ds(const dnssec_chain_ctx *ctx, const char *zone)
{
	for(const pending_ds_node *pd = ctx ? ctx->pending_ds : NULL; pd; pd = pd->next)
		if(strcasecmp(pd->zone, zone) == 0)
			return true;

	return false;
}

void dnssec_chain_try_validate_dnskeys(dnssec_chain_ctx *ctx, const struct packet *dnskey_response,
									   const char *zone)
{
	if(zone && dnssec_chain_has_pending_ds(ctx, zone))
		dnssec_chain_process_referral(ctx, dnskey_response, 0);
}

int dnssec_chain_add_response_keys(dnssec_chain_ctx *ctx, const struct packet *response,
								   const char *zone)
{
	if(!ctx || !response || !response->request || !zone || response->recv_len < HEADER_LEN)
		return 0;
	const uint8_t *buf = (const uint8_t *)response->request;
	int added = 0;
	rr_iter it; dns_rr rr;
	for(rr_iter_init(&it, buf, (int)response->recv_len); rr_next(&it, &rr); ) {
		dnskey_rdata dk;
		if(rr.type != QTYPE_DNSKEY || parse_dnskey_rdata(buf + rr.rdata, rr.rdlen, &dk) != 0)
			continue;
		uint16_t tag = compute_key_tag(dk.flags, dk.protocol, dk.algorithm, dk.pubkey, dk.pubkey_len);
		if(add_key(ctx, zone, &dk, tag) == 0)
			added++;
		free_dnskey_rdata(&dk);
	}

	return added;
}

int dnssec_chain_zone_bogus(const dnssec_chain_ctx *ctx, const char *zone)
{
	if(!ctx || !zone)
		return 0;
	for(const validated_key *vk = ctx->keys; vk; vk = vk->next)
		if(strcasecmp(vk->zone, zone) == 0)
			return 0;      // secure
	// only a DS we could have checked proves the zone should be signed
	for(const pending_ds_node *pd = ctx->pending_ds; pd; pd = pd->next)
		if(strcasecmp(pd->zone, zone) == 0 && ds_digest(pd->ds.digest_type))
			return 1;

	return 0;
}
