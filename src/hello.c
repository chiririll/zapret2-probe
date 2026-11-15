#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "common.h"

#ifndef TEMPLATE_DIR
#define TEMPLATE_DIR "/usr/share/zapret2/probe/templates"
#endif

void rand_bytes(void *p, size_t n)
{
	int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	size_t got = 0;
	if (fd >= 0) {
		while (got < n) {
			ssize_t r = read(fd, (uint8_t *)p + got, n - got);
			if (r <= 0) break;
			got += r;
		}
		close(fd);
	}
	for (; got < n; got++) ((uint8_t *)p)[got] = (uint8_t)rand();
}

typedef struct { uint8_t *b; size_t cap, len; int err; } wbuf;

static void w8(wbuf *w, uint8_t v)
{
	if (w->len + 1 > w->cap) { w->err = 1; return; }
	w->b[w->len++] = v;
}
static void w16(wbuf *w, unsigned v) { w8(w, v >> 8); w8(w, v); }
static void wbytes(wbuf *w, const void *p, size_t n)
{
	if (w->len + n > w->cap) { w->err = 1; return; }
	memcpy(w->b + w->len, p, n);
	w->len += n;
}
static void wrand(wbuf *w, size_t n)
{
	if (w->len + n > w->cap) { w->err = 1; return; }
	rand_bytes(w->b + w->len, n);
	w->len += n;
}
/* length prefix helpers: open returns position, close backpatches */
static size_t open16(wbuf *w) { size_t p = w->len; w16(w, 0); return p; }
static size_t open24(wbuf *w) { size_t p = w->len; w8(w, 0); w16(w, 0); return p; }
static size_t open8(wbuf *w) { size_t p = w->len; w8(w, 0); return p; }
static void close16(wbuf *w, size_t p)
{
	if (w->err) return;
	size_t l = w->len - p - 2;
	w->b[p] = l >> 8; w->b[p + 1] = l;
}
static void close24(wbuf *w, size_t p)
{
	if (w->err) return;
	size_t l = w->len - p - 3;
	w->b[p] = l >> 16; w->b[p + 1] = l >> 8; w->b[p + 2] = l;
}
static void close8(wbuf *w, size_t p) { if (!w->err) w->b[p] = w->len - p - 1; }

static unsigned grease(void)
{
	uint8_t r;
	rand_bytes(&r, 1);
	unsigned g = (r & 0xf0) | 0x0a;
	return g << 8 | g;
}

/* valid-looking ML-KEM-768 encapsulation key: 3*256 coefficients < 3329 packed in 12 bits, + rho */
static void mlkem_ek(wbuf *w)
{
	for (int i = 0; i < 3 * 256 / 2; i++) {
		uint8_t r[4];
		rand_bytes(r, 4);
		unsigned a = ((r[0] << 8 | r[1]) & 0xfff) % 3329;
		unsigned b = ((r[2] << 8 | r[3]) & 0xfff) % 3329;
		w8(w, a); w8(w, (a >> 8) | (b << 4)); w8(w, b >> 4);
	}
	wrand(w, 32);
}

static void ext_sni(wbuf *w, const char *sni)
{
	size_t n = strlen(sni);
	w16(w, 0);
	size_t e = open16(w);
	size_t l = open16(w);
	w8(w, 0);
	w16(w, n);
	wbytes(w, sni, n);
	close16(w, l); close16(w, e);
}

static void ext_u16list(wbuf *w, unsigned type, const unsigned *v, int n)
{
	w16(w, type);
	size_t e = open16(w);
	size_t l = open16(w);
	for (int i = 0; i < n; i++) w16(w, v[i]);
	close16(w, l); close16(w, e);
}

/* ClientHello handshake message modelled after a current Chrome: GREASE, X25519MLKEM768 */
static void build_msg(wbuf *w, const char *sni, bool quic, const uint8_t *scid, size_t scid_len)
{
	unsigned g1 = grease(), g2 = grease(), g3 = grease();
	w8(w, 1);
	size_t hs = open24(w);
	w16(w, 0x0303);
	wrand(w, 32);
	if (quic) w8(w, 0);
	else { w8(w, 32); wrand(w, 32); }
	size_t cs = open16(w);
	if (!quic) w16(w, g1);
	w16(w, 0x1301); w16(w, 0x1302); w16(w, 0x1303);
	if (!quic) {
		static const unsigned old[] = { 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
						0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035 };
		for (unsigned i = 0; i < sizeof old / sizeof *old; i++) w16(w, old[i]);
	}
	close16(w, cs);
	w8(w, 1); w8(w, 0);
	size_t ex = open16(w);

	if (!quic) { w16(w, g2); w16(w, 0); }
	ext_sni(w, sni);
	if (!quic) {
		w16(w, 23); w16(w, 0);                      /* extended_master_secret */
		w16(w, 0xff01); w16(w, 1); w8(w, 0);        /* renegotiation_info */
	}
	{
		unsigned grp[] = { g3, 0x11ec, 0x001d, 0x0017, 0x0018 };
		if (quic) ext_u16list(w, 10, grp + 1, 4); else ext_u16list(w, 10, grp, 5);
	}
	if (!quic) {
		w16(w, 11); w16(w, 2); w8(w, 1); w8(w, 0);  /* ec_point_formats */
		w16(w, 35); w16(w, 0);                      /* session_ticket */
	}
	{                                                   /* ALPN */
		w16(w, 16);
		size_t e = open16(w), l = open16(w);
		if (quic) { w8(w, 2); wbytes(w, "h3", 2); }
		else { w8(w, 2); wbytes(w, "h2", 2); w8(w, 8); wbytes(w, "http/1.1", 8); }
		close16(w, l); close16(w, e);
	}
	if (!quic) {
		w16(w, 5); w16(w, 5); w8(w, 1); w16(w, 0); w16(w, 0);  /* status_request */
	}
	{
		static const unsigned sa[] = { 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601 };
		ext_u16list(w, 13, sa, 8);
	}
	if (!quic) { w16(w, 18); w16(w, 0); }               /* signed_certificate_timestamp */
	{                                                   /* key_share */
		w16(w, 51);
		size_t e = open16(w), l = open16(w);
		if (!quic) { w16(w, g3); w16(w, 1); w8(w, 0); }
		w16(w, 0x11ec);
		size_t k = open16(w);
		mlkem_ek(w);
		wrand(w, 32);                               /* x25519 half of the hybrid share */
		close16(w, k);
		w16(w, 0x001d); w16(w, 32); wrand(w, 32);
		close16(w, l); close16(w, e);
	}
	w16(w, 45); w16(w, 2); w8(w, 1); w8(w, 1);          /* psk_key_exchange_modes */
	{                                                   /* supported_versions */
		w16(w, 43);
		size_t e = open16(w), l = open8(w);
		if (!quic) { w16(w, g1); w16(w, 0x0304); w16(w, 0x0303); }
		else w16(w, 0x0304);
		close8(w, l); close16(w, e);
	}
	if (!quic) {
		w16(w, 27); w16(w, 3); w8(w, 2); w16(w, 2);  /* compress_certificate: brotli */
		w16(w, 0x44cd); w16(w, 5); w16(w, 3); w8(w, 2); wbytes(w, "h2", 2); /* ALPS */
		w16(w, g2 ^ 0x1010); w16(w, 1); w8(w, 0);
	} else {
		w16(w, 0x39);
		size_t e = open16(w);
		static const uint8_t tp[] = {
			0x01, 0x04, 0x80, 0x00, 0x75, 0x30,             /* max_idle_timeout */
			0x03, 0x02, 0x45, 0xc0,                         /* max_udp_payload_size */
			0x04, 0x04, 0x80, 0xf0, 0x00, 0x00,             /* initial_max_data */
			0x05, 0x04, 0x80, 0x60, 0x00, 0x00,
			0x06, 0x04, 0x80, 0x60, 0x00, 0x00,
			0x07, 0x04, 0x80, 0x60, 0x00, 0x00,
			0x08, 0x02, 0x40, 0x64,                         /* max_streams_bidi */
			0x09, 0x02, 0x40, 0x67,                         /* max_streams_uni */
		};
		wbytes(w, tp, sizeof tp);
		w8(w, 0x0f); w8(w, scid_len); wbytes(w, scid, scid_len);
		close16(w, e);
	}
	close16(w, ex);
	close24(w, hs);
}

size_t hello_build_tcp(uint8_t *out, size_t cap, const char *sni)
{
	wbuf w = { out, cap, 0, 0 };
	w8(&w, 0x16); w16(&w, 0x0301);
	size_t rl = open16(&w);
	build_msg(&w, sni, false, NULL, 0);
	close16(&w, rl);
	return w.err ? 0 : w.len;
}

size_t hello_build_quic(uint8_t *out, size_t cap, const char *sni, const uint8_t *scid, size_t scid_len)
{
	wbuf w = { out, cap, 0, 0 };
	build_msg(&w, sni, true, scid, scid_len);
	return w.err ? 0 : w.len;
}

static unsigned be16(const uint8_t *p) { return p[0] << 8 | p[1]; }

/* locate server_name hostname inside a TLS record; fills offsets */
static bool find_sni(const uint8_t *r, size_t len, size_t *ext_len_pos, size_t *name_pos, size_t *name_len,
		     size_t *sess_pos, size_t *sess_len, size_t *exts_pos)
{
	if (len < 9 || r[0] != 0x16 || r[5] != 1) return false;
	if (5 + be16(r + 3) != len) return false;
	size_t p = 5 + 4 + 2 + 32;
	if (p >= len) return false;
	*sess_pos = p + 1; *sess_len = r[p];
	p += 1 + r[p];
	if (p + 2 > len) return false;
	p += 2 + be16(r + p);
	if (p + 1 > len) return false;
	p += 1 + r[p];
	if (p + 2 > len) return false;
	*exts_pos = p;
	size_t end = p + 2 + be16(r + p);
	if (end > len) return false;
	p += 2;
	while (p + 4 <= end) {
		unsigned t = be16(r + p), l = be16(r + p + 2);
		if (p + 4 + l > end) return false;
		if (t == 0) {
			if (l < 5 || r[p + 6] != 0) return false;
			*ext_len_pos = p + 2;
			*name_len = be16(r + p + 7);
			*name_pos = p + 9;
			return *name_pos + *name_len <= p + 4 + l;
		}
		p += 4 + l;
	}
	return false;
}

bool hello_get_sni(const uint8_t *r, size_t len, char *sni, size_t sl)
{
	size_t a, b, c, d, e, f;
	if (!find_sni(r, len, &a, &b, &c, &d, &e, &f) || c + 1 > sl) return false;
	memcpy(sni, r + b, c);
	sni[c] = 0;
	return true;
}

size_t hello_from_template(const uint8_t *tpl, size_t tlen, const char *sni, uint8_t *out, size_t cap)
{
	size_t extlen, np, nl, sp, sl, exts;
	if (!find_sni(tpl, tlen, &extlen, &np, &nl, &sp, &sl, &exts)) return 0;
	size_t n = strlen(sni);
	long delta = (long)n - (long)nl;
	if (n > 253 || tlen + delta > cap) return 0;
	memcpy(out, tpl, np);
	memcpy(out + np, sni, n);
	memcpy(out + np + n, tpl + np + nl, tlen - np - nl);
	size_t total = tlen + delta;
#define ADJ16(pos) do { unsigned v = be16(out + (pos)) + delta; out[pos] = v >> 8; out[(pos) + 1] = v; } while (0)
	ADJ16(3);                       /* record length */
	{ unsigned v = ((out[6] << 16) | (out[7] << 8) | out[8]) + delta;
	  out[6] = v >> 16; out[7] = v >> 8; out[8] = v; }  /* handshake length */
	ADJ16(exts);                    /* extensions length */
	ADJ16(extlen);                  /* server_name ext length */
	ADJ16(extlen + 2);              /* server_name list length */
	ADJ16(np - 2);                  /* name length */
	rand_bytes(out + 11, 32);
	if (sl) rand_bytes(out + sp, sl);
	return total;
}

size_t hello_load(const probe_opts *o, uint8_t *out, size_t cap)
{
	if (!o->template_path || !strcmp(o->template_path, "builtin") || !strcmp(o->template_path, "chrome"))
		return hello_build_tcp(out, cap, o->host);
	uint8_t tpl[4096];
	char path[512];
	FILE *f = NULL;
	/* a bare name (no '/') is looked up as <dir>/<name>.bin; dir is $ZPROBE_TEMPLATES or the install dir */
	if (!strchr(o->template_path, '/')) {
		const char *dir = getenv("ZPROBE_TEMPLATES");
		snprintf(path, sizeof path, "%s/%s.bin", dir ? dir : TEMPLATE_DIR, o->template_path);
		f = fopen(path, "rb");
	}
	if (!f) f = fopen(o->template_path, "rb");
	if (!f) return 0;
	size_t n = fread(tpl, 1, sizeof tpl, f);
	fclose(f);
	return hello_from_template(tpl, n, o->host, out, cap);
}
