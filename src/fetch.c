#define _GNU_SOURCE
/* zprobe fetch: full TLS handshake and an HTTP download, to tell "hello passes" from "page loads".
 * DPIs that let the ClientHello through but stop the flow after ~16-35 KB look healthy to the hello probe
 * and dead to a browser; this probe counts bytes on the TCP connection until --min-bytes arrive. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include "common.h"

#ifndef WITH_MBEDTLS

void probe_fetch(const probe_opts *o, const struct sockaddr_storage *ss, socklen_t sl, presult *r)
{
	memset(r, 0, sizeof *r);
	r->cls = RC_ERROR;
	set_detail(r, "no_mbedtls");
}

#else

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#define DEFAULT_CA "/etc/ssl/certs/ca-certificates.crt"
#define MAX_REQUESTS 64          /* keep-alive repeats of a short page */
#define IO_CHUNK 16384

typedef struct {
	int fd;
	uint64_t rx, tx;         /* bytes on the TCP connection */
	int err;                 /* errno of the last failed socket call */
	bool eof;
} bio_t;

static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
	bio_t *b = ctx;
	ssize_t n = send(b->fd, buf, len, MSG_NOSIGNAL);
	if (n >= 0) { b->tx += n; return (int)n; }
	if (errno == EAGAIN || errno == EINTR) return MBEDTLS_ERR_SSL_WANT_WRITE;
	b->err = errno;
	return errno == EPIPE || errno == ECONNRESET ? MBEDTLS_ERR_NET_CONN_RESET : MBEDTLS_ERR_NET_SEND_FAILED;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len)
{
	bio_t *b = ctx;
	ssize_t n = recv(b->fd, buf, len, 0);
	if (n > 0) { b->rx += n; return (int)n; }
	if (n == 0) { b->eof = true; return 0; }
	if (errno == EAGAIN || errno == EINTR) return MBEDTLS_ERR_SSL_WANT_READ;
	b->err = errno;
	return errno == ECONNRESET ? MBEDTLS_ERR_NET_CONN_RESET : MBEDTLS_ERR_NET_RECV_FAILED;
}

/* process-wide state, set up once (a batch worker runs many jobs) */
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_x509_crt g_ca;
static char g_ca_path[256];
static bool g_ca_loaded, g_rng_ready;

static bool rng_init(void)
{
	if (g_rng_ready) return true;
	if (psa_crypto_init() != PSA_SUCCESS) return false;
	mbedtls_entropy_init(&g_entropy);
	mbedtls_ctr_drbg_init(&g_drbg);
	if (mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy, (const unsigned char *)"zprobe", 6)) return false;
	g_rng_ready = true;
	return true;
}

static void ca_init(const char *path)
{
	if (!path) path = DEFAULT_CA;
	if (g_ca_path[0] && !strcmp(g_ca_path, path)) return;
	if (g_ca_path[0]) mbedtls_x509_crt_free(&g_ca);
	mbedtls_x509_crt_init(&g_ca);
	snprintf(g_ca_path, sizeof g_ca_path, "%s", path);
	/* >0: some certificates in the bundle did not parse, the rest are still loaded */
	g_ca_loaded = mbedtls_x509_crt_parse_file(&g_ca, path) >= 0 && g_ca.version != 0;
}

/* one HTTP response on a keep-alive connection: where does it end? */
typedef struct {
	char hdr[16384];
	size_t hlen;
	bool hdone, chunked, close_delim;
	int64_t clen;            /* -1 unknown */
	int64_t body;
	char tail[5];            /* last bytes, for the chunked terminator */
	int status;
} resp_t;

static void resp_reset(resp_t *p) { memset(p, 0, sizeof *p); p->clen = -1; }

static void resp_headers(resp_t *p)
{
	char *line = strstr(p->hdr, "\r\n");
	if (!line) return;
	if (!strncmp(p->hdr, "HTTP/", 5) && p->hlen > 12) p->status = atoi(p->hdr + 9);
	for (line += 2; *line; ) {
		char *e = strstr(line, "\r\n");
		if (!e) break;
		*e = 0;
		if (!strncasecmp(line, "content-length:", 15)) p->clen = atoll(line + 15);
		else if (!strncasecmp(line, "transfer-encoding:", 18) && strcasestr(line + 18, "chunked")) p->chunked = true;
		else if (!strncasecmp(line, "connection:", 11) && strcasestr(line + 11, "close")) p->close_delim = true;
		line = e + 2;
	}
	if (p->clen < 0 && !p->chunked) p->close_delim = true;
}

/* feeds decrypted bytes; returns true when the response is complete */
static bool resp_feed(resp_t *p, const uint8_t *b, size_t n)
{
	size_t i = 0;
	while (!p->hdone && i < n) {
		if (p->hlen + 1 >= sizeof p->hdr) { p->hdone = p->close_delim = true; break; }   /* absurd headers: read to the end */
		p->hdr[p->hlen++] = b[i++];
		p->hdr[p->hlen] = 0;
		if (p->hlen >= 4 && !memcmp(p->hdr + p->hlen - 4, "\r\n\r\n", 4)) {
			resp_headers(p);
			p->hdone = true;
		}
	}
	b += i; n -= i;
	if (!p->hdone || p->close_delim) return false;
	p->body += n;
	if (p->chunked) {
		for (size_t k = 0; k < n; k++) { memmove(p->tail, p->tail + 1, 4); p->tail[4] = b[k]; }
		return !memcmp(p->tail, "0\r\n\r\n", 5);
	}
	/* a 1xx/204/304 or HEAD-like answer has no body; treat clen 0 as complete once headers ended */
	return p->clen >= 0 && p->body >= p->clen;
}

/* --dump: the headers and the (de-chunked) body of the first response, for the controller to read.
 * Bytes above 0x7e become '?', so the result is plain ASCII and always valid JSON text. */
typedef struct {
	char *p;
	size_t len, cap, body, max;
	bool hdone, chunked, done;
	bool raw;                /* keep bytes as they are (Lua fetch) instead of ASCII-only */
	bool keep;               /* at max stop storing but do not end the capture */
	size_t hend;             /* length of the header block */
	int cs;                  /* chunk state: 0 size line, 1 data, 2 CR LF after data, 3 trailer/end */
	size_t left;
	char line[24];
	size_t ll;
} dump_t;

static void dump_put(dump_t *d, unsigned char c)
{
	if (d->len + 2 > d->cap) {
		size_t nc = d->cap ? d->cap * 2 : 4096;
		char *np = realloc(d->p, nc);
		if (!np) { d->done = true; return; }
		d->p = np; d->cap = nc;
	}
	d->p[d->len++] = d->raw || (c >= 0x20 && c < 0x7f) ? c : (c == '\n' || c == '\r' || c == '\t' ? c : '?');
	d->p[d->len] = 0;
}

static void dump_feed(dump_t *d, const uint8_t *b, size_t n)
{
	for (size_t i = 0; i < n && !d->done; i++) {
		if (!d->hdone) {
			dump_put(d, b[i]);
			if (d->len > 65536) { d->done = true; break; }
			if (d->len >= 4 && !memcmp(d->p + d->len - 4, "\r\n\r\n", 4)) {
				d->hdone = true;
				d->hend = d->len;
				d->chunked = false;
				for (char *l = d->p; l && *l; ) {
					if (!strncasecmp(l, "transfer-encoding:", 18) && strcasestr(l, "chunked") &&
					    strcasestr(l, "chunked") < strstr(l, "\r\n")) d->chunked = true;
					l = strstr(l, "\r\n");
					if (l) l += 2;
				}
			}
			continue;
		}
		if (!d->chunked) {
			if (d->body >= d->max) { if (d->keep) continue; d->done = true; break; }
			dump_put(d, b[i]); d->body++;
			continue;
		}
		switch (d->cs) {
		case 0:
			if (b[i] == '\n') {
				d->line[d->ll] = 0;
				d->left = strtoul(d->line, NULL, 16);
				d->ll = 0;
				if (d->left == 0) { d->cs = 3; d->done = true; } else d->cs = 1;
			} else if (d->ll + 1 < sizeof d->line) d->line[d->ll++] = b[i];
			break;
		case 1:
			if (d->body >= d->max) { if (!d->keep) { d->done = true; break; } }
			else { dump_put(d, b[i]); d->body++; }
			if (--d->left == 0) d->cs = 2;
			break;
		case 2:
			if (b[i] == '\n') d->cs = 0;
			break;
		}
	}
}

static int tls_fail_class(int ret, const bio_t *b, presult *r, const char *phase)
{
	if (ret == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE) { r->cls = RC_ALERT; set_detail(r, "%s_alert", phase); }
	else if (ret == MBEDTLS_ERR_NET_CONN_RESET || ret == MBEDTLS_ERR_SSL_CONN_EOF || b->eof) {
		r->cls = RC_RST; set_detail(r, "%s_%s", phase, b->eof ? "eof" : "reset");
	} else if (ret == MBEDTLS_ERR_NET_SEND_FAILED || ret == MBEDTLS_ERR_NET_RECV_FAILED) {
		r->cls = RC_RST; set_detail(r, "%s_%s", phase, strerror(b->err));
	} else {
		r->cls = RC_FORGED; set_detail(r, "%s_tls_%04x", phase, (unsigned)-ret);
	}
	return -1;
}

static int write_all(mbedtls_ssl_context *ssl, bio_t *b, const char *buf, size_t len, int64_t deadline)
{
	while (len) {
		int n = mbedtls_ssl_write(ssl, (const unsigned char *)buf, len);
		if (n > 0) { buf += n; len -= n; continue; }
		if (n == MBEDTLS_ERR_SSL_WANT_WRITE || n == MBEDTLS_ERR_SSL_WANT_READ) {
			if (net_wait(b->fd, n == MBEDTLS_ERR_SSL_WANT_WRITE ? POLLOUT : POLLIN, deadline)) return MBEDTLS_ERR_SSL_TIMEOUT;
			continue;
		}
		return n;
	}
	return 0;
}

void probe_fetch(const probe_opts *o, const struct sockaddr_storage *ss, socklen_t sl, presult *r)
{
	memset(r, 0, sizeof *r);
	int min_bytes = o->min_bytes > 0 ? o->min_bytes : 65536;
	if (!rng_init()) { r->cls = RC_ERROR; set_detail(r, "rng_init"); return; }
	ca_init(o->ca);

	bio_t b = { .fd = net_socket(ss->ss_family, SOCK_STREAM, o->mark) };
	if (b.fd < 0) { r->cls = RC_ERROR; set_detail(r, "socket_%s", strerror(errno)); return; }
	int64_t t0 = now_ms();
	int e = net_connect(b.fd, ss, sl, o->timeout_ms);
	r->connect_ms = (int)(now_ms() - t0);
	if (e) { net_conn_fail(r, e); close(b.fd); return; }

	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	int ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret) { r->cls = RC_ERROR; set_detail(r, "ssl_config"); goto out; }
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &g_drbg);
	/* verify afterwards and judge only the name (and the chain if we have roots): a router's clock is often wrong */
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	if (g_ca_loaded) mbedtls_ssl_conf_ca_chain(&conf, &g_ca, NULL);
	if (mbedtls_ssl_setup(&ssl, &conf) || mbedtls_ssl_set_hostname(&ssl, o->host)) {
		r->cls = RC_ERROR; set_detail(r, "ssl_setup");
		goto out;
	}
	mbedtls_ssl_set_bio(&ssl, &b, bio_send, bio_recv, NULL);

	/* handshake: no reply to the hello is the DPI's "blocked", same as the hello probe */
	int64_t th = now_ms(), dl = th + o->timeout_ms;
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			if (net_wait(b.fd, ret == MBEDTLS_ERR_SSL_WANT_WRITE ? POLLOUT : POLLIN, dl)) {
				r->cls = RC_TIMEOUT; set_detail(r, b.rx ? "hs_partial" : "hs_no_reply");
				r->bytes = (int)b.rx;
				goto out;
			}
			continue;
		}
		tls_fail_class(ret, &b, r, "hs");
		r->bytes = (int)b.rx;
		goto out;
	}
	r->hs_ms = (int)(now_ms() - th);

	uint32_t vf = mbedtls_ssl_get_verify_result(&ssl);
	if (vf & MBEDTLS_X509_BADCERT_CN_MISMATCH) { r->cls = RC_FORGED; set_detail(r, "cert_name"); goto out; }
	if (g_ca_loaded && (vf & MBEDTLS_X509_BADCERT_NOT_TRUSTED)) { r->cls = RC_FORGED; set_detail(r, "cert_untrusted"); goto out; }

	const char *method = o->method ? o->method : "GET";
	bool head = !strcmp(method, "HEAD");
	bool ua = o->hdrs && (strcasestr(o->hdrs, "user-agent:") != NULL), acc = o->hdrs && (strcasestr(o->hdrs, "accept:") != NULL);
	size_t cap_req = 512 + strlen(o->path ? o->path : "/") + strlen(o->host) + (o->hdrs ? strlen(o->hdrs) : 0) + o->body_len;
	char *req = malloc(cap_req);
	if (!req) { r->cls = RC_ERROR; set_detail(r, "oom"); goto out; }
	int rl = snprintf(req, cap_req, "%s %s HTTP/1.1\r\nHost: %s\r\n%s%sAccept-Encoding: identity\r\nConnection: keep-alive\r\n",
			  method, o->path ? o->path : "/", o->host,
			  ua ? "" : "User-Agent: Mozilla/5.0\r\n", acc ? "" : "Accept: */*\r\n");
	if (o->hdrs) rl += snprintf(req + rl, cap_req - rl, "%s", o->hdrs);
	if (o->body_len) rl += snprintf(req + rl, cap_req - rl, "Content-Length: %zu\r\n", o->body_len);
	rl += snprintf(req + rl, cap_req - rl, "\r\n");
	if (o->body_len) { memcpy(req + rl, o->body, o->body_len); rl += o->body_len; }

	bool cap = o->once;      /* Lua fetch: send once, keep the raw response, see the cases below */
	int64_t t1 = now_ms();
	resp_t resp;
	resp_reset(&resp);
	int nreq = 1;
	dump_t dmp = { .max = cap ? o->max_body : (o->dump > 0 ? (size_t)o->dump : 0), .raw = cap, .keep = cap };
	if ((ret = write_all(&ssl, &b, req, rl, t1 + o->timeout_ms)) != 0) {
		if (ret == MBEDTLS_ERR_SSL_TIMEOUT) { r->cls = RC_STALLED; set_detail(r, "send_stall"); }
		else tls_fail_class(ret, &b, r, "send");
		r->bytes = (int)b.rx;
		free(req);
		goto out;
	}
	uint8_t buf[IO_CHUNK];
	dl = now_ms() + o->timeout_ms;        /* inactivity limit, moved on every byte */
	for (;;) {
		if (cap ? (o->min_bytes > 0 && (int64_t)b.rx >= o->min_bytes) : (!dmp.max && (int64_t)b.rx >= min_bytes)) {
			r->cls = RC_OK; set_detail(r, "bytes_%d", (int)b.rx); break;
		}
		ret = mbedtls_ssl_read(&ssl, buf, sizeof buf);
		if (ret > 0) {
			dl = now_ms() + o->timeout_ms;
			bool done = resp_feed(&resp, buf, ret);
			if (resp.status && !r->status) r->status = resp.status;
			if (cap) {
				dump_feed(&dmp, buf, ret);
				if (dmp.hdone && o->stop_headers) { r->cls = RC_OK; set_detail(r, "headers"); break; }
				if (dmp.hdone && (head || resp.status == 204 || resp.status == 304 || resp.status / 100 == 1)) done = true;
				if (done || dmp.done) { r->cls = RC_OK; set_detail(r, "complete_%d", (int)b.rx); break; }
				continue;
			}
			if (dmp.max && nreq == 1) {
				dump_feed(&dmp, buf, ret);
				if (done || dmp.done) { r->cls = RC_OK; set_detail(r, "dump_%zu", dmp.len); break; }
				continue;
			}
			if (done && (int64_t)b.rx < min_bytes) {
				if (nreq >= MAX_REQUESTS) { r->cls = RC_OK; set_detail(r, "short_%d", (int)b.rx); break; }
				resp_reset(&resp);
				nreq++;
				if (write_all(&ssl, &b, req, rl, dl) != 0) { r->cls = RC_RST; set_detail(r, "send_failed"); break; }
			}
			continue;
		}
		if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			if (net_wait(b.fd, ret == MBEDTLS_ERR_SSL_WANT_WRITE ? POLLOUT : POLLIN, dl)) {
				/* handshake done, bytes stopped before min-bytes: the throttling signature */
				r->cls = RC_STALLED; set_detail(r, "stall_%d", (int)b.rx);
				break;
			}
			continue;
		}
		if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) continue;
		if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			/* the server finished first: the page was smaller than min-bytes, inconclusive for the controller */
			if (cap) {
				if (!dmp.hdone) { r->cls = RC_RST; set_detail(r, "eof_no_response"); break; }
				r->cls = RC_OK; set_detail(r, "complete_%d", (int)b.rx);
				break;
			}
			if (dmp.max && dmp.len) { r->cls = RC_OK; set_detail(r, "dump_%zu", dmp.len); break; }
			r->cls = RC_OK; set_detail(r, "short_%d", (int)b.rx);
			break;
		}
		tls_fail_class(ret, &b, r, "data");
		break;
	}
	r->ms = (int)(now_ms() - t1);
	r->bytes = (int)b.rx;
	free(req);
	if (cap && dmp.len) {
		size_t hl = dmp.hdone ? dmp.hend : dmp.len;
		r->rhdr = malloc(hl + 1);
		r->rbody = malloc(dmp.len - hl + 1);
		if (r->rhdr && r->rbody) {
			memcpy(r->rhdr, dmp.p, hl); r->rhdr[hl] = 0; r->rhdr_len = hl;
			memcpy(r->rbody, dmp.p + hl, dmp.len - hl); r->rbody[dmp.len - hl] = 0; r->rbody_len = dmp.len - hl;
		} else { free(r->rhdr); free(r->rbody); r->rhdr = r->rbody = NULL; r->rhdr_len = r->rbody_len = 0; }
	} else if (dmp.len) { r->dump = dmp.p; dmp.p = NULL; }
	free(dmp.p);
out:
	if (!r->ms) r->ms = (int)(now_ms() - t0);
	if (!r->bytes) r->bytes = (int)b.rx;
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	close(b.fd);
}

#endif
