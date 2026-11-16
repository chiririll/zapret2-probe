#define _GNU_SOURCE
#include <errno.h>
#include <netdb.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "common.h"
#include "json.h"

#define VERSION "0.1.0"

static void usage(FILE *f)
{
	fputs("usage: zprobe <tls|quic|http|fetch|dns|batch|hello> [options]\n"
	      "  --host NAME        SNI / Host header / name to resolve\n"
	      "  --ip ADDR          connect here instead of resolving --host\n"
	      "  --port N           default 443 (tls, quic), 80 (http)\n"
	      "  --mark 0xHEX       SO_MARK for every socket (needs CAP_NET_ADMIN)\n"
	      "  --user NAME        drop root to NAME after startup; keeps only CAP_NET_ADMIN, and only if --mark/marks are used\n"
	      "  --timeout MS       per probe, default 5000\n"
	      "  --repeat N         probes per job, default 1\n"
	      "  --pace-ms MS       pause between repeats\n"
	      "  --template NAME|FILE   tls: ClientHello template (builtin or a captured record file)\n"
	      "  --path P           http, fetch: request path, default /\n"
	      "  --min-bytes N      fetch: ok once N bytes came back on the connection (handshake included), default 65536\n"
	      "  --ca FILE          fetch: CA bundle, default /etc/ssl/certs/ca-certificates.crt\n"
	      "  --server IP        dns: resolver (default: first in /etc/resolv.conf)\n"
	      "  --ref IP           dns: second resolver for comparison\n"
	      "  --wait MS          dns: wait for extra replies after the first (injection check), default 300\n"
	      "  -4 / -6            address family\n"
	      "  --parallel N       batch: concurrent jobs, default 1\n"
	      "  --json             accepted for compatibility; output is always JSON\n"
	      "batch reads JSON lines from stdin: {\"id\":\"1\",\"cmd\":\"tls\",\"host\":\"example.com\",\"mark\":\"0x08010000\"}\n"
	      "exit status: 0 if every probe was ok, 1 otherwise, 2 on usage errors\n", f);
}

static void opts_default(probe_opts *o)
{
	memset(o, 0, sizeof *o);
	o->timeout_ms = 5000;
	o->repeat = 1;
	o->dns_wait_ms = 300;
	o->min_bytes = 65536;
}

static int cmp_int(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }

/* runs one job, appends one JSON object to out; returns number of non-ok probes */
static int run_job(const char *cmd, const probe_opts *o, const char *id, sbuf *out)
{
	bool dns = !strcmp(cmd, "dns"), fetch = !strcmp(cmd, "fetch");
	int port = o->port ? o->port : !strcmp(cmd, "http") ? 80 : 443;
	struct sockaddr_storage ss;
	socklen_t sl = 0;
	int rep = o->repeat < 1 ? 1 : o->repeat > 1000 ? 1000 : o->repeat;
	presult *res = calloc(rep, sizeof *res);
	int counts[RC_COUNT] = { 0 };
	int *ms = calloc(rep, sizeof *ms);
	int nms = 0, bad = 0;
	char ipstr[64] = "";
	bool resolved = true;

	if (!o->host) { fputs("zprobe: --host is required\n", stderr); free(res); free(ms); return -1; }
	if (!dns) {
		int st = !strcmp(cmd, "quic") ? SOCK_DGRAM : SOCK_STREAM;
		resolved = net_resolve(o->host, o->ip, o->family, port, st, &ss, &sl) == 0;
		if (resolved) {
			getnameinfo((struct sockaddr *)&ss, sl, ipstr, sizeof ipstr, NULL, 0, 1 /* NI_NUMERICHOST */);
		}
	}
	for (int i = 0; i < rep; i++) {
		memset(&res[i], 0, sizeof res[i]);
		if (!resolved) { res[i].cls = RC_UNREACHABLE; set_detail(&res[i], "resolve_failed"); }
		else if (!strcmp(cmd, "tls")) probe_tls(o, &ss, sl, &res[i]);
		else if (!strcmp(cmd, "quic")) probe_quic(o, &ss, sl, &res[i]);
		else if (!strcmp(cmd, "http")) probe_http(o, &ss, sl, &res[i]);
		else if (!strcmp(cmd, "fetch")) probe_fetch(o, &ss, sl, &res[i]);
		else probe_dns(o, &res[i]);
		counts[res[i].cls]++;
		if (res[i].cls == RC_OK) ms[nms++] = res[i].ms; else bad++;
		if (i + 1 < rep && o->pace_ms > 0) usleep(o->pace_ms * 1000);
	}
	/* overall class: all ok -> ok, otherwise the most frequent failure */
	result_class best = RC_OK;
	if (counts[RC_OK] != rep) {
		int top = -1;
		for (int c = 0; c < RC_COUNT; c++)
			if (c != RC_OK && counts[c] > top) { top = counts[c]; best = c; }
	}
	qsort(ms, nms, sizeof *ms, cmp_int);

	sb_puts(out, "{");
	if (id) { sb_puts(out, "\"id\":"); sb_jstr(out, id); sb_puts(out, ","); }
	sb_printf(out, "\"proto\":\"%s\",\"host\":", cmd);
	sb_jstr(out, o->host);
	if (!dns) { sb_puts(out, ",\"ip\":"); sb_jstr(out, ipstr); sb_printf(out, ",\"port\":%d", port); }
	if (o->mark) sb_printf(out, ",\"mark\":\"0x%08x\"", o->mark);
	sb_printf(out, ",\"repeat\":%d,\"ok\":%d,\"class\":\"%s\",\"counts\":{", rep, counts[RC_OK], class_name(best));
	bool first = true;
	for (int c = 0; c < RC_COUNT; c++)
		if (counts[c]) { sb_printf(out, "%s\"%s\":%d", first ? "" : ",", class_name(c), counts[c]); first = false; }
	sb_puts(out, "}");
	if (nms) sb_printf(out, ",\"median_ms\":%d", ms[nms / 2]);
	sb_puts(out, ",\"results\":[");
	for (int i = 0; i < rep; i++) {
		sb_printf(out, "%s{\"class\":\"%s\",\"ms\":%d", i ? "," : "", class_name(res[i].cls), res[i].ms);
		if (!dns) sb_printf(out, ",\"connect_ms\":%d", res[i].connect_ms);
		if (res[i].status) sb_printf(out, ",\"status\":%d", res[i].status);
		if (fetch) sb_printf(out, ",\"bytes\":%d,\"hs_ms\":%d", res[i].bytes, res[i].hs_ms);
		if (res[i].detail[0]) { sb_puts(out, ",\"detail\":"); sb_jstr(out, res[i].detail); }
		if (dns && res[i].info[0]) {
			sb_puts(out, ",\"answers\":[");
			char tmp[256];
			snprintf(tmp, sizeof tmp, "%s", res[i].info);
			bool f2 = true;
			for (char *s = strtok(tmp, " "); s; s = strtok(NULL, " ")) {
				if (!f2) sb_puts(out, ",");
				sb_jstr(out, s);
				f2 = false;
			}
			sb_puts(out, "]");
		}
		sb_puts(out, "}");
	}
	sb_puts(out, "]}");
	free(res); free(ms);
	return bad;
}

static uint32_t parse_mark(const char *s) { return (uint32_t)strtoul(s, NULL, 0); }

static int cmd_hello(const probe_opts *o)
{
	uint8_t buf[4096];
	if (!o->host) { fputs("zprobe: --host is required\n", stderr); return 2; }
	size_t n = hello_load(o, buf, sizeof buf);
	if (!n) { fputs("zprobe: cannot build ClientHello\n", stderr); return 1; }
	return fwrite(buf, 1, n, stdout) == n ? 0 : 1;
}

static int cmd_batch(const probe_opts *base, int parallel, int pace_ms)
{
	char *line = NULL;
	size_t cap = 0;
	int running = 0, failed = 0, lineno = 0;
	ssize_t len;
	while ((len = getline(&line, &cap, stdin)) >= 0) {
		kv a[24];
		lineno++;
		char *t = line;
		while (*t == ' ' || *t == '\t') t++;
		if (!*t || *t == '\n') continue;
		int n = json_parse_flat(t, a, 24);
		if (n < 0) { fprintf(stderr, "zprobe: batch line %d: invalid JSON\n", lineno); failed++; continue; }
		probe_opts o = *base;
		char host[256], ip[64], path[256], server[64], ref[64], tpl[256], ca[256], cmd[16], id[64];
		const char *v;
#define STR(key, dst, field) do { if ((v = kv_get(a, n, key))) { snprintf(dst, sizeof dst, "%s", v); o.field = dst; } } while (0)
#define NUM(key, field) do { if ((v = kv_get(a, n, key))) o.field = atoi(v); } while (0)
		STR("host", host, host); STR("ip", ip, ip); STR("path", path, path);
		STR("server", server, server); STR("ref", ref, ref); STR("template", tpl, template_path); STR("ca", ca, ca);
		NUM("port", port); NUM("timeout", timeout_ms); NUM("repeat", repeat); NUM("family", family);
		NUM("pace_ms", pace_ms); NUM("min_bytes", min_bytes);
		if ((v = kv_get(a, n, "mark"))) o.mark = parse_mark(v);
		snprintf(cmd, sizeof cmd, "%s", (v = kv_get(a, n, "cmd")) ? v : "tls");
		snprintf(id, sizeof id, "%s", (v = kv_get(a, n, "id")) ? v : "");
		if (strcmp(cmd, "tls") && strcmp(cmd, "quic") && strcmp(cmd, "http") && strcmp(cmd, "fetch") && strcmp(cmd, "dns")) {
			fprintf(stderr, "zprobe: batch line %d: unknown cmd '%s'\n", lineno, cmd);
			failed++;
			continue;
		}
		while (running >= parallel) { int st; if (wait(&st) > 0) { running--; } else break; }
		fflush(stdout);
		pid_t pid = parallel > 1 ? fork() : 0;
		if (pid == 0) {
			sbuf out;
			sb_init(&out);
			int bad = run_job(cmd, &o, id[0] ? id : NULL, &out);
			sb_puts(&out, "\n");
			if (bad >= 0) {
				if (parallel > 1) { ssize_t w = write(1, out.p, out.len); (void)w; }
				else fwrite(out.p, 1, out.len, stdout);
			}
			sb_free(&out);
			if (parallel > 1) _exit(bad != 0);
			if (bad) failed++;
		} else if (pid > 0) running++;
		else { perror("fork"); failed++; }
		if (pace_ms > 0) usleep(pace_ms * 1000);
	}
	int st;
	pid_t w;
	/* exit statuses of children only tell "something failed"; batch exit code is advisory */
	while ((w = wait(&st)) > 0) if (WIFEXITED(st) && WEXITSTATUS(st)) failed++;
	free(line);
	fflush(stdout);
	return failed ? 1 : 0;
}

int main(int argc, char **argv)
{
	probe_opts o;
	int parallel = 1;
	const char *user = NULL;
	static const struct option lo[] = {
		{ "host", 1, 0, 'H' }, { "ip", 1, 0, 'i' }, { "port", 1, 0, 'p' }, { "mark", 1, 0, 'm' },
		{ "timeout", 1, 0, 't' }, { "repeat", 1, 0, 'r' }, { "pace-ms", 1, 0, 'P' },
		{ "template", 1, 0, 'T' }, { "path", 1, 0, 'a' }, { "server", 1, 0, 's' }, { "ref", 1, 0, 'R' },
		{ "wait", 1, 0, 'w' }, { "parallel", 1, 0, 'j' }, { "json", 0, 0, 'J' }, { "help", 0, 0, 'h' },
		{ "version", 0, 0, 'V' }, { "user", 1, 0, 'u' }, { "min-bytes", 1, 0, 'b' }, { "ca", 1, 0, 'c' }, { 0 }
	};
	opts_default(&o);
	signal(SIGPIPE, SIG_IGN);
	if (argc < 2) { usage(stderr); return 2; }
	if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) { usage(stdout); return 0; }
	if (!strcmp(argv[1], "--version")) { puts("zprobe " VERSION); return 0; }
	const char *cmd = argv[1];
	optind = 2;
	int c;
	while ((c = getopt_long(argc, argv, "46h", lo, NULL)) != -1) {
		switch (c) {
		case 'H': o.host = optarg; break;
		case 'i': o.ip = optarg; break;
		case 'p': o.port = atoi(optarg); break;
		case 'm': o.mark = parse_mark(optarg); break;
		case 't': o.timeout_ms = atoi(optarg); break;
		case 'r': o.repeat = atoi(optarg); break;
		case 'P': o.pace_ms = atoi(optarg); break;
		case 'T': o.template_path = optarg; break;
		case 'a': o.path = optarg; break;
		case 's': o.server = optarg; break;
		case 'R': o.ref = optarg; break;
		case 'w': o.dns_wait_ms = atoi(optarg); break;
		case 'j': parallel = atoi(optarg) < 1 ? 1 : atoi(optarg); break;
		case '4': o.family = 4; break;
		case '6': o.family = 6; break;
		case 'u': user = optarg; break;
		case 'b': o.min_bytes = atoi(optarg); break;
		case 'c': o.ca = optarg; break;
		case 'J': break;
		case 'h': usage(stdout); return 0;
		case 'V': puts("zprobe " VERSION); return 0;
		default: usage(stderr); return 2;
		}
	}
	if (o.timeout_ms < 1) o.timeout_ms = 5000;
	/* batch jobs may carry their own marks, so keep CAP_NET_ADMIN there */
	if (user && priv_drop(user, o.mark || !strcmp(cmd, "batch"))) return 2;
	if (!strcmp(cmd, "batch")) return cmd_batch(&o, parallel, o.pace_ms);
	if (!strcmp(cmd, "hello")) return cmd_hello(&o);
	if (strcmp(cmd, "tls") && strcmp(cmd, "quic") && strcmp(cmd, "http") && strcmp(cmd, "fetch") && strcmp(cmd, "dns")) {
		fprintf(stderr, "zprobe: unknown command '%s'\n", cmd);
		usage(stderr);
		return 2;
	}
	sbuf out;
	sb_init(&out);
	int bad = run_job(cmd, &o, NULL, &out);
	if (bad < 0) return 2;
	puts(out.p);
	sb_free(&out);
	return bad ? 1 : 0;
}
