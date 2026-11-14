#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "common.h"

static void conn_fail(presult *r, int e)
{
	r->cls = e == ECONNRESET ? RC_RST : RC_UNREACHABLE;
	set_detail(r, "connect_%s", e == ETIMEDOUT ? "timeout" : e == ECONNREFUSED ? "refused" :
		   e == ECONNRESET ? "reset" : e == EHOSTUNREACH ? "hostunreach" : e == ENETUNREACH ? "netunreach" : "error");
}

/* send one request over a fresh TCP connection and classify the first answer */
static void tcp_exchange(const probe_opts *o, const struct sockaddr_storage *ss, socklen_t sl,
			 const uint8_t *req, size_t rl, bool http, presult *r)
{
	int fd = net_socket(ss->ss_family, SOCK_STREAM, o->mark);
	if (fd < 0) {
		r->cls = RC_ERROR; set_detail(r, "socket_%s", strerror(errno));
		return;
	}
	int64_t t0 = now_ms();
	int e = net_connect(fd, ss, sl, o->timeout_ms);
	r->connect_ms = (int)(now_ms() - t0);
	if (e) { conn_fail(r, e); close(fd); return; }
	int64_t t1 = now_ms(), dl = t1 + o->timeout_ms;
	if (net_write_all(fd, req, rl, dl) < 0) {
		r->cls = (errno == ECONNRESET || errno == EPIPE) ? RC_RST : RC_TIMEOUT;
		set_detail(r, "send_%s", strerror(errno));
		close(fd);
		return;
	}
	uint8_t buf[8192];
	size_t n = 0;
	for (;;) {
		ssize_t k = net_read(fd, buf + n, sizeof buf - n, dl);
		if (k > 0) {
			n += k;
			if (http ? http_classify(buf, n, o->host, false, r) : tls_classify(buf, n, r)) break;
			if (n == sizeof buf) { r->cls = RC_FORGED; set_detail(r, "oversize"); break; }
			continue;
		}
		if (k == 0) {
			if (n && http && http_classify(buf, n, o->host, true, r)) break;
			r->cls = RC_RST; set_detail(r, n ? "eof_partial" : "eof");
			break;
		}
		if (errno == ETIMEDOUT) { r->cls = RC_TIMEOUT; set_detail(r, n ? "partial" : "no_reply"); }
		else { r->cls = RC_RST; set_detail(r, "recv_%s", strerror(errno)); }
		break;
	}
	r->ms = (int)(now_ms() - t1);
	close(fd);
}

void probe_tls(const probe_opts *o, const struct sockaddr_storage *ss, socklen_t sl, presult *r)
{
	uint8_t hello[4096];
	memset(r, 0, sizeof *r);
	size_t hl = hello_load(o, hello, sizeof hello);
	if (!hl) { r->cls = RC_ERROR; set_detail(r, "hello_build"); return; }
	tcp_exchange(o, ss, sl, hello, hl, false, r);
}

void probe_http(const probe_opts *o, const struct sockaddr_storage *ss, socklen_t sl, presult *r)
{
	char req[1024];
	memset(r, 0, sizeof *r);
	int n = snprintf(req, sizeof req,
			 "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
			 o->path ? o->path : "/", o->host);
	if (n <= 0 || (size_t)n >= sizeof req) { r->cls = RC_ERROR; set_detail(r, "request_too_long"); return; }
	tcp_exchange(o, ss, sl, (const uint8_t *)req, n, true, r);
}

void probe_quic(const probe_opts *o, const struct sockaddr_storage *ss, socklen_t sl, presult *r)
{
	memset(r, 0, sizeof *r);
	uint8_t dcid[8], scid[8], msg[2048], pkt[1500];
	rand_bytes(dcid, 8); rand_bytes(scid, 8);
	size_t ml = hello_build_quic(msg, sizeof msg, o->host, scid, 8);
	quic_keys k;
	uint8_t pkt2[1500];
	size_t pl = 0, pl2 = 0, chunk = quic_initial_max_chunk(8, 8);
	if (ml && quic_initial_keys(dcid, 8, false, &k) == 0) {
		/* a ClientHello with ML-KEM does not fit one packet: split the CRYPTO stream like Chrome does */
		size_t c1 = ml < chunk ? ml : chunk;
		pl = quic_seal_initial(pkt, sizeof pkt, &k, dcid, 8, scid, 8, msg, c1, 1200, 0, 0);
		if (pl && ml > c1) pl2 = quic_seal_initial(pkt2, sizeof pkt2, &k, dcid, 8, scid, 8, msg + c1, ml - c1, 1200, c1, 1);
		if (ml > c1 && !pl2) pl = 0;
	}
	if (!pl) { r->cls = RC_ERROR; set_detail(r, "initial_build"); return; }
	int fd = net_socket(ss->ss_family, SOCK_DGRAM, o->mark);
	if (fd < 0) { r->cls = RC_ERROR; set_detail(r, "socket_%s", strerror(errno)); return; }
	if (connect(fd, (const struct sockaddr *)ss, sl) < 0) { conn_fail(r, errno); close(fd); return; }
	int64_t t1 = now_ms(), dl = t1 + o->timeout_ms;
	if (send(fd, pkt, pl, 0) < 0 || (pl2 && send(fd, pkt2, pl2, 0) < 0)) {
		r->cls = errno == ECONNREFUSED ? RC_UNREACHABLE : RC_ERROR;
		set_detail(r, "send_%s", strerror(errno));
		close(fd);
		return;
	}
	uint8_t buf[2048];
	for (;;) {
		ssize_t n = net_read(fd, buf, sizeof buf, dl);
		if (n > 0) {
			if (quic_classify(buf, n, dcid, 8, r)) break;
			continue;
		}
		if (n < 0 && errno == ETIMEDOUT) { r->cls = RC_TIMEOUT; set_detail(r, "no_reply"); }
		else { r->cls = RC_UNREACHABLE; set_detail(r, "icmp_%s", strerror(errno)); }
		break;
	}
	r->ms = (int)(now_ms() - t1);
	close(fd);
}
