#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "common.h"

size_t dns_build_query(uint8_t *out, size_t cap, uint16_t id, const char *name, uint16_t type)
{
	size_t n = strlen(name), p = 12;
	if (n > 253 || cap < n + 18) return 0;
	memset(out, 0, 12);
	out[0] = id >> 8; out[1] = id; out[2] = 0x01; out[5] = 1;
	while (*name) {
		const char *dot = strchr(name, '.');
		size_t l = dot ? (size_t)(dot - name) : strlen(name);
		if (!l || l > 63) return 0;
		out[p++] = l;
		memcpy(out + p, name, l); p += l;
		name += l + (dot ? 1 : 0);
	}
	out[p++] = 0;
	out[p++] = type >> 8; out[p++] = type;
	out[p++] = 0; out[p++] = 1;
	return p;
}

static int skip_name(const uint8_t *p, size_t n, size_t *i)
{
	for (int guard = 0; guard < 128; guard++) {
		if (*i >= n) return -1;
		uint8_t l = p[*i];
		if (!l) { (*i)++; return 0; }
		if ((l & 0xc0) == 0xc0) { *i += 2; return *i <= n ? 0 : -1; }
		if (l & 0xc0) return -1;
		*i += 1 + l;
	}
	return -1;
}

int dns_parse_answers(const uint8_t *p, size_t n, uint16_t *id, char *out, size_t osz)
{
	if (n < 12 || !(p[2] & 0x80)) return -1;
	*id = p[0] << 8 | p[1];
	if ((p[3] & 0x0f) != 0) return -2 - (p[3] & 0x0f);   /* rcode: -3 = NXDOMAIN... */
	unsigned qd = p[4] << 8 | p[5], an = p[6] << 8 | p[7];
	size_t i = 12, o = 0, cnt = 0;
	out[0] = 0;
	for (unsigned q = 0; q < qd; q++) {
		if (skip_name(p, n, &i) < 0 || i + 4 > n) return -1;
		i += 4;
	}
	for (unsigned a = 0; a < an; a++) {
		if (skip_name(p, n, &i) < 0 || i + 10 > n) return -1;
		unsigned t = p[i] << 8 | p[i + 1], rl = p[i + 8] << 8 | p[i + 9];
		i += 10;
		if (i + rl > n) return -1;
		char ip[INET6_ADDRSTRLEN];
		if (t == 1 && rl == 4) inet_ntop(AF_INET, p + i, ip, sizeof ip);
		else if (t == 28 && rl == 16) inet_ntop(AF_INET6, p + i, ip, sizeof ip);
		else { i += rl; continue; }
		int w = snprintf(out + o, osz - o, "%s%s", o ? " " : "", ip);
		if (w > 0 && o + w < osz) o += w;
		cnt++;
		i += rl;
	}
	return (int)cnt;
}

bool ip_is_bogon(const char *ip)
{
	struct in_addr a;
	struct in6_addr a6;
	if (inet_pton(AF_INET, ip, &a) == 1) {
		uint32_t v = ntohl(a.s_addr);
		return (v >> 24) == 0 || (v >> 24) == 127 || (v >> 24) == 10 || (v >> 20) == 0xac1 ||
		       (v >> 16) == 0xc0a8 || (v >> 16) == 0xa9fe || v >= 0xe0000000;
	}
	if (inet_pton(AF_INET6, ip, &a6) == 1) {
		static const uint8_t zero[16];
		if (!memcmp(&a6, zero, 16)) return true;
		if (a6.s6_addr[15] == 1 && !memcmp(&a6, zero, 15)) return true;
		return (a6.s6_addr[0] & 0xfe) == 0xfc || (a6.s6_addr[0] == 0xfe && (a6.s6_addr[1] & 0xc0) == 0x80);
	}
	return false;
}

static int default_server(char *out, size_t osz)
{
	FILE *f = fopen("/etc/resolv.conf", "r");
	char line[256];
	snprintf(out, osz, "8.8.8.8");
	if (!f) return 0;
	while (fgets(line, sizeof line, f)) {
		char a[128];
		if (sscanf(line, "nameserver %127s", a) == 1 && !strchr(a, '%')) {
			snprintf(out, osz, "%s", a);
			break;
		}
	}
	fclose(f);
	return 0;
}

/* one query; collects every reply seen until dns_wait after the first */
static int query_server(const probe_opts *o, const char *server, const uint8_t *q, size_t ql, uint16_t id,
			char answers[][256], int maxr, int *rcode, int *first_ms)
{
	struct sockaddr_storage ss;
	socklen_t sl;
	if (net_resolve(NULL, server, o->family, 53, SOCK_DGRAM, &ss, &sl)) return -1;
	int fd = net_socket(ss.ss_family, SOCK_DGRAM, o->mark);
	if (fd < 0) return -1;
	if (connect(fd, (struct sockaddr *)&ss, sl) < 0 || send(fd, q, ql, 0) < 0) { close(fd); return -1; }
	int64_t t0 = now_ms(), dl = t0 + o->timeout_ms;
	int nr = 0;
	*rcode = 0;
	for (;;) {
		uint8_t buf[1500];
		ssize_t n = net_read(fd, buf, sizeof buf, dl);
		if (n <= 0) break;
		uint16_t rid;
		int c = dns_parse_answers(buf, n, &rid, answers[nr < maxr ? nr : maxr - 1], 256);
		if (rid != id) continue;
		if (c < -1) { *rcode = -c - 2; c = 0; }
		if (c < 0) continue;
		if (nr == 0) { *first_ms = (int)(now_ms() - t0); dl = now_ms() + o->dns_wait_ms; }
		if (nr < maxr) nr++;
		if (nr >= maxr) break;
	}
	close(fd);
	return nr;
}

void probe_dns(const probe_opts *o, presult *r)
{
	memset(r, 0, sizeof *r);
	char srv[128];
	const char *server = o->server;
	if (!server) { default_server(srv, sizeof srv); server = srv; }
	uint8_t q[300];
	uint16_t id;
	rand_bytes(&id, 2);
	size_t ql = dns_build_query(q, sizeof q, id, o->host, 1);
	if (!ql) { r->cls = RC_ERROR; set_detail(r, "bad_name"); return; }
	char ans[4][256] = { "", "", "", "" };
	int rcode, ms = 0;
	int nr = query_server(o, server, q, ql, id, ans, 4, &rcode, &ms);
	if (nr < 0) { r->cls = RC_ERROR; set_detail(r, "query_%s", strerror(errno)); return; }
	if (nr == 0) { r->cls = RC_TIMEOUT; set_detail(r, "no_reply"); return; }
	r->ms = ms;
	snprintf(r->info, sizeof r->info, "%s", ans[0]);
	r->cls = RC_OK;
	if (rcode) { r->cls = RC_ERROR; set_detail(r, "rcode_%d", rcode); return; }
	if (nr > 1 && strcmp(ans[0], ans[1])) {
		r->cls = RC_DNS_SPOOFED; set_detail(r, "multiple_replies");
		return;
	}
	if (nr > 1) set_detail(r, "duplicate_reply");
	char tmp[256];
	snprintf(tmp, sizeof tmp, "%s", ans[0]);
	for (char *s = strtok(tmp, " "); s; s = strtok(NULL, " "))
		if (ip_is_bogon(s)) { r->cls = RC_DNS_SPOOFED; set_detail(r, "bogon_%s", s); return; }
	if (o->ref) {
		char rans[4][256] = { "", "", "", "" };
		int rc2, ms2;
		uint16_t id2;
		rand_bytes(&id2, 2);
		ql = dns_build_query(q, sizeof q, id2, o->host, 1);
		int n2 = query_server(o, o->ref, q, ql, id2, rans, 4, &rc2, &ms2);
		if (n2 > 0 && !rc2) {
			bool overlap = false;
			char a[256], b[256];
			snprintf(a, sizeof a, "%s", ans[0]);
			for (char *s = strtok(a, " "); s && !overlap; s = strtok(NULL, " ")) {
				snprintf(b, sizeof b, "%s", rans[0]);
				for (char *t = strtok(b, " "); t; t = strtok(NULL, " ")) if (!strcmp(s, t)) overlap = true;
			}
			if (!overlap) set_detail(r, "differs_from_ref"); /* CDNs legitimately differ: not a verdict */
		}
	}
}
