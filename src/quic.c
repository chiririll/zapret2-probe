#include <string.h>
#include "common.h"
#include "sha.h"
#include "aes.h"
#include "gcm.h"
#include "aes-gcm.h"

static const uint8_t salt_v1[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

static int expand_label(const uint8_t *secret, const char *label, uint8_t *out, size_t olen)
{
	uint8_t info[64];
	size_t ll = strlen(label), p = 0;
	info[p++] = olen >> 8; info[p++] = olen;
	info[p++] = 6 + ll;
	memcpy(info + p, "tls13 ", 6); p += 6;
	memcpy(info + p, label, ll); p += ll;
	info[p++] = 0;
	return hkdfExpand(SHA256, secret, SHA256HashSize, info, p, out, olen);
}

int quic_initial_keys(const uint8_t *dcid, size_t dl, bool server, quic_keys *k)
{
	uint8_t init[SHA256HashSize], sec[SHA256HashSize];
	aes_init_keygen_tables();
	if (hkdfExtract(SHA256, salt_v1, sizeof salt_v1, dcid, dl, init)) return -1;
	if (expand_label(init, server ? "server in" : "client in", sec, 32)) return -1;
	if (expand_label(sec, "quic key", k->key, 16) || expand_label(sec, "quic iv", k->iv, 12) ||
	    expand_label(sec, "quic hp", k->hp, 16)) return -1;
	return 0;
}

static size_t get_varint(const uint8_t *p, size_t avail, uint64_t *v)
{
	if (!avail) return 0;
	size_t l = 1u << (p[0] >> 6);
	if (l > avail) return 0;
	uint64_t x = p[0] & 0x3f;
	for (size_t i = 1; i < l; i++) x = x << 8 | p[i];
	*v = x;
	return l;
}

static int hp_mask(const uint8_t *hp, const uint8_t *sample, uint8_t mask[16])
{
	aes_context c;
	if (aes_setkey(&c, AES_ENCRYPT, hp, 16)) return -1;
	return aes_cipher(&c, sample, mask);
}

size_t quic_seal_initial(uint8_t *out, size_t cap, const quic_keys *k,
			 const uint8_t *dcid, size_t dl, const uint8_t *scid, size_t sl,
			 const uint8_t *crypto, size_t clen, size_t min_total,
			 uint64_t coff, uint32_t pn)
{
	const size_t pnlen = 2;
	size_t hdr = 1 + 4 + 1 + dl + 1 + sl + 1 + 2 + pnlen;
	size_t frame = 1 + 2 + 2 + clen;             /* type, 2-byte offset, 2-byte length, data */
	size_t plen = frame;
	if (hdr + plen + 16 < min_total) plen = min_total - hdr - 16;
	if (plen < 20 - pnlen) plen = 20 - pnlen;    /* header-protection sample needs 4+16 bytes after pn start */
	if (clen > 16000 || coff > 16000 || hdr + plen + 16 > cap) return 0;
	uint8_t *p = out;
	*p++ = 0xc0 | (pnlen - 1);
	*p++ = 0; *p++ = 0; *p++ = 0; *p++ = 1;
	*p++ = dl; memcpy(p, dcid, dl); p += dl;
	*p++ = sl; memcpy(p, scid, sl); p += sl;
	*p++ = 0;                                    /* token length */
	uint64_t lv = pnlen + plen + 16;
	*p++ = 0x40 | (lv >> 8); *p++ = lv;
	size_t pn_off = p - out;
	*p++ = pn >> 8; *p++ = pn;                   /* 2-byte packet number */
	uint8_t *payload = p;
	memset(payload, 0, plen);
	payload[0] = 0x06;
	payload[1] = 0x40 | (coff >> 8); payload[2] = coff;
	payload[3] = 0x40 | (clen >> 8); payload[4] = clen;
	memcpy(payload + 5, crypto, clen);
	uint8_t tag[16];
	aes_init_keygen_tables();
	uint8_t iv[12];
	memcpy(iv, k->iv, 12);
	iv[10] ^= pn >> 8; iv[11] ^= pn;
	if (aes_gcm_crypt(AES_ENCRYPT, payload, payload, plen, k->key, 16, iv, 12, out, hdr, tag, 16)) return 0;
	memcpy(payload + plen, tag, 16);
	uint8_t mask[16];
	if (hp_mask(k->hp, out + pn_off + 4, mask)) return 0;
	out[0] ^= mask[0] & 0x0f;
	out[pn_off] ^= mask[1];
	out[pn_off + 1] ^= mask[2];
	return hdr + plen + 16;
}

bool quic_open_initial(const uint8_t *pkt, size_t len, const quic_keys *k, uint8_t *plain, size_t *plen)
{
	if (len < 7 || !(pkt[0] & 0x80)) return false;
	size_t off = 5;
	if (off + 1 + pkt[off] + 1 > len) return false;
	off += 1 + pkt[off];
	if (off + 1 + pkt[off] > len) return false;
	off += 1 + pkt[off];
	uint64_t tl, pl;
	size_t n = get_varint(pkt + off, len - off, &tl);
	if (!n || tl > len) return false;
	off += n + tl;
	if (off >= len || !(n = get_varint(pkt + off, len - off, &pl))) return false;
	off += n;
	size_t pn_off = off;
	if (pl < 20 || pn_off + pl > len) return false;
	uint8_t mask[16];
	aes_init_keygen_tables();
	if (hp_mask(k->hp, pkt + pn_off + 4, mask)) return false;
	uint8_t b0 = pkt[0] ^ (mask[0] & 0x0f);
	size_t pnlen = (b0 & 3) + 1;
	uint32_t pn = 0;
	uint8_t hdr[512];
	if (pn_off + pnlen > sizeof hdr) return false;
	memcpy(hdr, pkt, pn_off + pnlen);
	hdr[0] = b0;
	for (size_t i = 0; i < pnlen; i++) {
		hdr[pn_off + i] = pkt[pn_off + i] ^ mask[1 + i];
		pn = pn << 8 | hdr[pn_off + i];
	}
	uint8_t iv[12];
	memcpy(iv, k->iv, 12);
	for (int i = 0; i < 4; i++) iv[11 - i] ^= pn >> (8 * i);
	if (pl < pnlen + 16) return false;
	size_t clen = pl - pnlen - 16;
	if (clen > *plen) return false;
	uint8_t tag[16];
	if (aes_gcm_crypt(AES_DECRYPT, plain, pkt + pn_off + pnlen, clen, k->key, 16, iv, 12,
			  hdr, pn_off + pnlen, tag, 16)) return false;
	if (memcmp(tag, pkt + pn_off + pnlen + clen, 16)) return false;
	*plen = clen;
	return true;
}

int quic_crypto_first(const uint8_t *p, size_t n, uint8_t *b)
{
	size_t i = 0;
	while (i < n) {
		uint64_t v, off, l;
		size_t m;
		switch (p[i]) {
		case 0x00: case 0x01: i++; break;
		case 0x02: case 0x03: {
			int ecn = p[i] == 0x03;
			uint64_t cnt = 0;
			i++;
			for (int f = 0; f < 4; f++) {      /* largest, delay, range count, first range */
				if (!(m = get_varint(p + i, n - i, &v))) return 0;
				if (f == 2) cnt = v;
				i += m;
			}
			for (uint64_t c = 0; c < cnt * 2; c++) {
				if (!(m = get_varint(p + i, n - i, &v))) return 0;
				i += m;
			}
			for (int f = 0; ecn && f < 3; f++) {
				if (!(m = get_varint(p + i, n - i, &v))) return 0;
				i += m;
			}
			break;
		}
		case 0x06:
			i++;
			if (!(m = get_varint(p + i, n - i, &off))) return 0;
			i += m;
			if (!(m = get_varint(p + i, n - i, &l))) return 0;
			i += m;
			if (l && i < n && off == 0) { *b = p[i]; return 1; }
			i += l;
			break;
		default:
			return 0;
		}
	}
	return 0;
}

bool quic_classify(const uint8_t *dg, size_t n, const uint8_t *dcid, size_t dl, presult *r)
{
	if (n < 5 || !(dg[0] & 0x80)) {
		r->cls = RC_FORGED; set_detail(r, "not_long_header");
		return true;
	}
	uint32_t ver = dg[1] << 24 | dg[2] << 16 | dg[3] << 8 | dg[4];
	if (ver == 0) { r->cls = RC_OK; set_detail(r, "version_negotiation"); return true; }
	if (((dg[0] >> 4) & 3) == 3) { r->cls = RC_OK; set_detail(r, "retry"); return true; }
	quic_keys k;
	uint8_t plain[2048];
	size_t pl = sizeof plain;
	if (((dg[0] >> 4) & 3) == 0 && quic_initial_keys(dcid, dl, true, &k) == 0 &&
	    quic_open_initial(dg, n, &k, plain, &pl)) {
		uint8_t b;
		r->cls = RC_OK;
		set_detail(r, quic_crypto_first(plain, pl, &b) && b == 2 ? "server_hello" : "initial");
		return true;
	}
	r->cls = RC_FORGED; set_detail(r, "undecryptable");
	return true;
}

size_t quic_initial_max_chunk(size_t dl, size_t sl)
{
	size_t hdr = 1 + 4 + 1 + dl + 1 + sl + 1 + 2 + 2;
	return 1200 - hdr - 16 - 5;
}
