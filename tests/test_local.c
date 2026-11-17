/* Loopback integration tests: real sockets against forked fake servers. No root needed (mark = 0). */
#define _GNU_SOURCE
#include "check.h"
#include "../src/common.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

enum { SRV_HELLO, SRV_RST, SRV_SILENT, SRV_ALERT, SRV_HTTP200, SRV_HTTP_EVIL, SRV_TLS_HTTP };

static pid_t spawn_tcp(int mode, int *port)
{
	int ls = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t l = sizeof a;
	bind(ls, (struct sockaddr *)&a, sizeof a);
	listen(ls, 4);
	getsockname(ls, (struct sockaddr *)&a, &l);
	*port = ntohs(a.sin_port);
	pid_t p = fork();
	if (p == 0) {
		int c = accept(ls, NULL, NULL);
		char buf[4096];
		ssize_t n = read(c, buf, sizeof buf);
		(void)n;
		static const unsigned char sh[] = { 0x16, 3, 3, 0, 4, 2, 0, 0, 0 };
		static const unsigned char al[] = { 0x15, 3, 3, 0, 2, 2, 112 };
		const char *ok = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
		const char *evil = "HTTP/1.1 302 Found\r\nLocation: http://blocked.isp.example/\r\n\r\n";
		switch (mode) {
		case SRV_HELLO: write(c, sh, sizeof sh); break;
		case SRV_ALERT: write(c, al, sizeof al); break;
		case SRV_RST: {
			struct linger lg = { 1, 0 };
			setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
			close(c);
			_exit(0);
		}
		case SRV_SILENT: sleep(3); break;
		case SRV_HTTP200: write(c, ok, strlen(ok)); break;
		case SRV_HTTP_EVIL: write(c, evil, strlen(evil)); break;
		case SRV_TLS_HTTP: write(c, ok, strlen(ok)); break;
		}
		usleep(200000);
		_exit(0);
	}
	close(ls);
	return p;
}

static void reap(pid_t p) { kill(p, SIGKILL); waitpid(p, NULL, 0); }

static struct sockaddr_storage addr_of(int port, socklen_t *sl)
{
	struct sockaddr_storage ss;
	struct sockaddr_in *a = (struct sockaddr_in *)&ss;
	memset(&ss, 0, sizeof ss);
	a->sin_family = AF_INET; a->sin_port = htons(port); a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	*sl = sizeof *a;
	return ss;
}

static result_class run(int mode, bool http, int timeout, presult *r)
{
	int port;
	pid_t p = spawn_tcp(mode, &port);
	socklen_t sl;
	struct sockaddr_storage ss = addr_of(port, &sl);
	probe_opts o = { .host = "example.com", .timeout_ms = timeout, .repeat = 1 };
	if (http) probe_http(&o, &ss, sl, r); else probe_tls(&o, &ss, sl, r);
	reap(p);
	return r->cls;
}

static void test_tcp(void)
{
	presult r;
	CHECK(run(SRV_HELLO, false, 2000, &r) == RC_OK && !strcmp(r.detail, "server_hello"));
	CHECK(run(SRV_ALERT, false, 2000, &r) == RC_ALERT && !strcmp(r.detail, "alert_112"));
	CHECK(run(SRV_RST, false, 2000, &r) == RC_RST);
	CHECK(run(SRV_SILENT, false, 400, &r) == RC_TIMEOUT && r.ms >= 300);
	CHECK(run(SRV_TLS_HTTP, false, 2000, &r) == RC_FORGED && !strcmp(r.detail, "http_response"));
	CHECK(run(SRV_HTTP200, true, 2000, &r) == RC_OK && r.status == 200);
	CHECK(run(SRV_HTTP_EVIL, true, 2000, &r) == RC_FORGED && !strcmp(r.detail, "redirect_foreign"));
	/* nothing listens: refused */
	int ls = socket(AF_INET, SOCK_STREAM, 0), port;
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t l = sizeof a;
	bind(ls, (struct sockaddr *)&a, sizeof a);
	getsockname(ls, (struct sockaddr *)&a, &l);
	port = ntohs(a.sin_port);
	close(ls);
	socklen_t sl;
	struct sockaddr_storage ss = addr_of(port, &sl);
	probe_opts o = { .host = "example.com", .timeout_ms = 1000, .repeat = 1 };
	probe_tls(&o, &ss, sl, &r);
	CHECK(r.cls == RC_UNREACHABLE && !strcmp(r.detail, "connect_refused"));
}

static pid_t spawn_quic(bool answer, int *port)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t l = sizeof a;
	bind(s, (struct sockaddr *)&a, sizeof a);
	getsockname(s, (struct sockaddr *)&a, &l);
	*port = ntohs(a.sin_port);
	pid_t p = fork();
	if (p == 0) {
		uint8_t buf[2000];
		struct sockaddr_in from;
		socklen_t fl = sizeof from;
		ssize_t n = recvfrom(s, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
		if (n > 0 && answer) {
			size_t dl = buf[5], sl = buf[6 + dl];
			quic_keys k;
			quic_initial_keys(buf + 6, dl, true, &k);
			uint8_t sh[8] = { 2, 0, 0, 4, 3, 3, 0, 0 }, out[300];
			size_t o = quic_seal_initial(out, sizeof out, &k, buf + 7 + dl, sl, buf + 6, dl, sh, sizeof sh, 100, 0, 0);
			sendto(s, out, o, 0, (struct sockaddr *)&from, fl);
		}
		sleep(3);
		_exit(0);
	}
	close(s);
	return p;
}

static void test_quic(void)
{
	presult r;
	probe_opts o = { .host = "example.com", .timeout_ms = 1500, .repeat = 1 };
	socklen_t sl;
	int port;
	pid_t p = spawn_quic(true, &port);
	struct sockaddr_storage ss = addr_of(port, &sl);
	probe_quic(&o, &ss, sl, &r);
	CHECK(r.cls == RC_OK && !strcmp(r.detail, "server_hello"));
	reap(p);
	o.timeout_ms = 400;
	p = spawn_quic(false, &port);
	ss = addr_of(port, &sl);
	probe_quic(&o, &ss, sl, &r);
	CHECK(r.cls == RC_TIMEOUT);
	reap(p);
}

static void test_cli(void)
{
	int port;
	pid_t p = spawn_tcp(SRV_HELLO, &port);
	char cmd[300], out[2048];
	snprintf(cmd, sizeof cmd, "" ZPROBE " tls --host example.com --ip 127.0.0.1 --port %d --repeat 1", port);
	FILE *f = popen(cmd, "r");
	size_t n = fread(out, 1, sizeof out - 1, f);
	out[n] = 0;
	int st = pclose(f);
	CHECK(WEXITSTATUS(st) == 0 && strstr(out, "\"class\":\"ok\"") && strstr(out, "\"proto\":\"tls\""));
	reap(p);
	p = spawn_tcp(SRV_RST, &port);
	snprintf(cmd, sizeof cmd, "" ZPROBE " tls --host example.com --ip 127.0.0.1 --port %d", port);
	f = popen(cmd, "r");
	n = fread(out, 1, sizeof out - 1, f);
	out[n] = 0;
	st = pclose(f);
	CHECK(WEXITSTATUS(st) == 1 && strstr(out, "\"class\":\"rst\""));
	reap(p);
	/* batch, two jobs in parallel */
	int p1, p2;
	pid_t a = spawn_tcp(SRV_HELLO, &p1), b = spawn_tcp(SRV_ALERT, &p2);
	snprintf(cmd, sizeof cmd,
		 "printf '{\"id\":\"a\",\"cmd\":\"tls\",\"host\":\"x.org\",\"ip\":\"127.0.0.1\",\"port\":%d}\\n"
		 "{\"id\":\"b\",\"cmd\":\"tls\",\"host\":\"y.org\",\"ip\":\"127.0.0.1\",\"port\":%d}\\n"
		 "garbage\\n' | " ZPROBE " batch --parallel 2 2>/dev/null", p1, p2);
	f = popen(cmd, "r");
	n = fread(out, 1, sizeof out - 1, f);
	out[n] = 0;
	st = pclose(f);
	CHECK(strstr(out, "\"id\":\"a\"") && strstr(out, "\"id\":\"b\"") && strstr(out, "\"class\":\"alert\""));
	CHECK(WEXITSTATUS(st) == 1);                /* bad line + failed probe */
	reap(a); reap(b);
	f = popen("" ZPROBE " bogus 2>/dev/null", "r");
	st = pclose(f);
	CHECK(WEXITSTATUS(st) == 2);
}

int main(void)
{
	signal(SIGPIPE, SIG_IGN);
	test_tcp();
	test_quic();
	test_cli();
	DONE();
}
