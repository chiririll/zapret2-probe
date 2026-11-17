/* Lua check runtime: primitives against loopback servers, the sandbox, limits, arguments, verdicts, batch.
 * Needs WITH_LUA=1. Scripts are written to a temporary directory; checks/ (the shipped ones) is on the path too. */
#define _GNU_SOURCE
#include "check.h"
#include "../src/check.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char g_dir[] = "/tmp/zprobe-test-check-XXXXXX";

static void script(const char *name, const char *text)
{
	char path[300];
	snprintf(path, sizeof path, "%s/%s.lua", g_dir, name);
	FILE *f = fopen(path, "wb");
	fputs(text, f);
	fclose(f);
}

static char *run(const char *name, const char *args, int repeat, int timeout, const char *phase)
{
	probe_opts o = { .timeout_ms = timeout, .repeat = repeat };
	sbuf out;
	sb_init(&out);
	run_check("j", &o, name, phase ? phase : "check", args, &out);
	return out.p;
}

#define HAS(out, s) (strstr((out), (s)) != NULL)

/* ---- loopback servers ---- */
enum { SRV_HELLO, SRV_ALERT, SRV_HTTP200, SRV_SILENT };

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
		for (;;) {
			int c = accept(ls, NULL, NULL);
			char buf[4096];
			ssize_t n = read(c, buf, sizeof buf);
			(void)n;
			static const unsigned char sh[] = { 0x16, 3, 3, 0, 4, 2, 0, 0, 0 };
			static const unsigned char al[] = { 0x15, 3, 3, 0, 2, 2, 112 };
			const char *ok = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
			ssize_t w;
			if (mode == SRV_HELLO) w = write(c, sh, sizeof sh);
			else if (mode == SRV_ALERT) w = write(c, al, sizeof al);
			else if (mode == SRV_HTTP200) w = write(c, ok, strlen(ok));
			else sleep(10);
			(void)w;
			close(c);
		}
	}
	close(ls);
	return p;
}

static pid_t spawn_udp(int *port)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t l = sizeof a;
	bind(s, (struct sockaddr *)&a, sizeof a);
	getsockname(s, (struct sockaddr *)&a, &l);
	*port = ntohs(a.sin_port);
	pid_t p = fork();
	if (p == 0) {
		for (;;) {
			char buf[512];
			struct sockaddr_in from;
			socklen_t fl = sizeof from;
			ssize_t n = recvfrom(s, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
			if (n <= 0) continue;
			if (n >= 4 && !memcmp(buf, "mute", 4)) continue;
			sendto(s, buf, n, 0, (struct sockaddr *)&from, fl);
			sendto(s, "second", 6, 0, (struct sockaddr *)&from, fl);
		}
	}
	close(s);
	return p;
}

static void reap(pid_t p) { kill(p, SIGKILL); waitpid(p, NULL, 0); }

static void test_primitives(void)
{
	script("prims",
	       "return { protos = {'tls'}, args = { port = {type='number', required=true}, mode = {required=true}, payload = {default='ping'} },\n"
	       " check = function(p, a)\n"
	       "  local r\n"
	       "  if a.mode == 'tls' then r = p:tls{host='example.com', ip='127.0.0.1', port=a.port}\n"
	       "  elseif a.mode == 'tls2' then p:tls{host='example.com', ip='127.0.0.1', port=a.port}; r = p:tls('example.com')\n"
	       "  elseif a.mode == 'http' then r = p:http{host='example.com', ip='127.0.0.1', port=a.port, path='/x'}\n"
	       "  elseif a.mode == 'udp' then r = p:udp{host='127.0.0.1', port=a.port, payload=a.payload, wait_ms=300}\n"
	       "  elseif a.mode == 'nohost' then r = p:tls{host='no-such-host.invalid'}\n"
	       "  elseif a.mode == 'badcall' then r = p:tls{}\n"
	       "  end\n"
	       "  local extra = r.replies and #r.replies > 0 and (#r.replies .. ':' .. r.replies[1] .. ':' .. r.replies[2]) or ''\n"
	       "  return p:ok(r.class .. '/' .. r.detail .. '/' .. tostring(r.status) .. '/' .. extra)\n"
	       " end }\n");
	int port;
	char args[200];
	char *o;
	pid_t s;

	s = spawn_tcp(SRV_HELLO, &port);
	snprintf(args, sizeof args, "{\"port\":%d,\"mode\":\"tls\"}", port);
	o = run("prims", args, 1, 2000, NULL);
	CHECK(HAS(o, "\"detail\":\"ok/server_hello/nil/\"") && HAS(o, "\"p\":\"tls\"") && HAS(o, "\"ip\":\"127.0.0.1\""));
	free(o);
	reap(s);

	s = spawn_tcp(SRV_ALERT, &port);
	snprintf(args, sizeof args, "{\"port\":%d,\"mode\":\"tls\"}", port);
	o = run("prims", args, 1, 2000, NULL);
	CHECK(HAS(o, "alert/alert_112") && HAS(o, "\"class\":\"alert\",\"ms\""));      /* the step keeps the probe's class */
	free(o);
	reap(s);

	s = spawn_tcp(SRV_HTTP200, &port);
	snprintf(args, sizeof args, "{\"port\":%d,\"mode\":\"http\"}", port);
	o = run("prims", args, 1, 2000, NULL);
	CHECK(HAS(o, "\"detail\":\"ok/http_200/200/\""));
	free(o);
	reap(s);

	s = spawn_tcp(SRV_SILENT, &port);
	snprintf(args, sizeof args, "{\"port\":%d,\"mode\":\"tls\"}", port);
	o = run("prims", args, 1, 400, NULL);
	CHECK(HAS(o, "timeout/no_reply"));
	free(o);
	reap(s);

	/* two calls: both steps are recorded, in order */
	s = spawn_tcp(SRV_HELLO, &port);
	snprintf(args, sizeof args, "{\"port\":%d,\"mode\":\"tls2\"}", port);
	o = run("prims", args, 1, 1500, NULL);
	CHECK(HAS(o, "\"steps\":[{\"p\":\"tls\"") && HAS(o, "},{\"p\":\"tls\""));
	free(o);
	reap(s);

	s = spawn_udp(&port);
	snprintf(args, sizeof args, "{\"port\":%d,\"mode\":\"udp\"}", port);
	o = run("prims", args, 1, 2000, NULL);
	CHECK(HAS(o, "ok/replies_2/nil/2:ping:second"));
	free(o);
	snprintf(args, sizeof args, "{\"port\":%d,\"mode\":\"udp\",\"payload\":\"mute\"}", port);
	o = run("prims", args, 1, 2000, NULL);
	CHECK(HAS(o, "timeout/no_reply"));
	free(o);
	reap(s);

	o = run("prims", "{\"port\":1,\"mode\":\"nohost\"}", 1, 2000, NULL);
	CHECK(HAS(o, "unreachable/resolve_failed"));
	free(o);
	o = run("prims", "{\"port\":1,\"mode\":\"badcall\"}", 1, 2000, NULL);
	CHECK(HAS(o, "script_error") && HAS(o, "no_host"));
	free(o);
}

static void test_verdicts_and_args(void)
{
	script("v",
	       "return { protos = {'tls','quic'}, args = { how = {default='ok'}, n = {type='number', default=5}, flag = {type='bool'},\n"
	       "   l = {type='list'}, s = {default='dflt'} },\n"
	       " check = function(p, a)\n"
	       "  p:report('n', a.n); p:report('flag', a.flag); p:report('l', a.l); p:report('s', a.s)\n"
	       "  p:report('proto', a.proto); p:report('stage', a.stage); p:report('prep', a.prepared)\n"
	       "  if a.how == 'fail' then return p:fail('rst', 'boom') end\n"
	       "  if a.how == 'badclass' then return p:fail('nonsense', 'x') end\n"
	       "  if a.how == 'inc' then return p:inconclusive('no_node') end\n"
	       "  if a.how == 'none' then return end\n"
	       "  if a.how == 'throw' then error('kaboom') end\n"
	       "  if a.how == 'late' then p:fail('forged', 'first'); return end\n"
	       "  return p:ok('fine')\n"
	       " end,\n"
	       " prepare = function(p, a) p:report('nodes', {'a','b'}); p:report('url', 'https://x/?a=1&b=\"2\"'); p:report('bin', 'a\\255b'); return p:ok() end }\n");
	char *o = run("v", NULL, 1, 1000, NULL);
	CHECK(HAS(o, "\"class\":\"ok\"") && HAS(o, "\"detail\":\"fine\"") && HAS(o, "\"proto\":\"check\"") && HAS(o, "\"id\":\"j\""));
	CHECK(HAS(o, "\"n\":5") && HAS(o, "\"s\":\"dflt\"") && HAS(o, "\"proto\":\"tls\"") && HAS(o, "\"stage\":\"confirm\"") && !HAS(o, "\"flag\""));
	free(o);
	o = run("v", "{\"n\":\"12\",\"flag\":\"true\",\"l\":\"a,b\",\"proto\":\"quic\",\"stage\":\"screen\",\"prepared\":{\"nodes\":[\"x\"],\"k\":1.5}}", 1, 1000, NULL);
	CHECK(HAS(o, "\"n\":12") && HAS(o, "\"flag\":true") && HAS(o, "\"l\":[\"a\",\"b\"]") && HAS(o, "\"proto\":\"quic\"") && HAS(o, "\"stage\":\"screen\""));
	CHECK(HAS(o, "\"prep\":{\"k\":1.5,\"nodes\":[\"x\"]}") || HAS(o, "\"prep\":{\"nodes\":[\"x\"],\"k\":1.5}"));
	free(o);
	o = run("v", "{\"l\":[\"p\",\"q\"],\"s\":\"caf\\u00e9 \\ud83d\\ude00\"}", 1, 1000, NULL);
	CHECK(HAS(o, "\"l\":[\"p\",\"q\"]") && HAS(o, "\"s\":\"caf\xc3\xa9 \xf0\x9f\x98\x80\""));
	free(o);

	o = run("v", "{\"how\":\"fail\"}", 1, 1000, NULL);
	CHECK(HAS(o, "\"class\":\"rst\"") && HAS(o, "\"detail\":\"boom\"") && HAS(o, "\"ok\":0"));
	free(o);
	o = run("v", "{\"how\":\"badclass\"}", 1, 1000, NULL);
	CHECK(HAS(o, "\"class\":\"error\"") && HAS(o, "\"detail\":\"x\""));
	free(o);
	o = run("v", "{\"how\":\"inc\"}", 1, 1000, NULL);
	CHECK(HAS(o, "\"class\":\"inconclusive\"") && HAS(o, "\"detail\":\"no_node\"") && HAS(o, "\"counts\":{\"inconclusive\":1}"));
	free(o);
	o = run("v", "{\"how\":\"none\"}", 1, 1000, NULL);
	CHECK(HAS(o, "\"detail\":\"no_verdict\""));
	free(o);
	o = run("v", "{\"how\":\"throw\"}", 1, 1000, NULL);
	CHECK(HAS(o, "\"detail\":\"script_error\"") && HAS(o, "kaboom"));
	free(o);
	o = run("v", "{\"how\":\"late\"}", 1, 1000, NULL);
	CHECK(HAS(o, "\"class\":\"forged\""));                 /* a verdict given without returning it still counts */
	free(o);
	o = run("v", "{\"how\":\"fail\"}", 3, 1000, NULL);
	CHECK(HAS(o, "\"repeat\":3") && HAS(o, "\"counts\":{\"rst\":3}"));
	free(o);

	/* argument errors become the result's detail, before the script runs */
	o = run("v", "{\"bogus\":1}", 1, 1000, NULL);
	CHECK(HAS(o, "\"detail\":\"bad_arg_bogus\"") && !HAS(o, "\"data\""));
	free(o);
	o = run("v", "{\"n\":\"abc\"}", 1, 1000, NULL);
	CHECK(HAS(o, "\"detail\":\"bad_arg_n\""));
	free(o);
	o = run("v", "{\"proto\":\"http\"}", 1, 1000, NULL);
	CHECK(HAS(o, "\"detail\":\"bad_proto_http\""));
	free(o);
	o = run("v", "{\"n\":", 1, 1000, NULL);
	CHECK(HAS(o, "\"detail\":\"bad_args\""));
	free(o);

	/* prepare: one call, its data comes back */
	o = run("v", NULL, 5, 1000, "prepare");
	CHECK(HAS(o, "\"phase\":\"prepare\"") && HAS(o, "\"repeat\":1") && HAS(o, "\"nodes\":[\"a\",\"b\"]"));
	CHECK(HAS(o, "\"url\":\"https://x/?a=1&b=\\\"2\\\"\"") && HAS(o, "\"bin\":\"a?b\""));     /* invalid UTF-8 cannot break the JSON */
	free(o);
	script("noprep", "return { protos = {'tls'}, check = function(p, a) return p:ok('x') end }\n");
	o = run("noprep", NULL, 1, 1000, "prepare");
	CHECK(HAS(o, "\"class\":\"ok\"") && HAS(o, "no_prepare"));
	free(o);
}

static void test_sandbox_and_limits(void)
{
	script("sand",
	       "return { protos = {'tls'}, check = function(p, a)\n"
	       "  local bad = {}\n"
	       "  for _, n in ipairs{'io','os','package','debug','ffi','jit','bit','dofile','loadfile','load','loadstring','print','getfenv','setfenv'} do\n"
	       "    if _G[n] ~= nil then bad[#bad+1] = n end end\n"
	       "  if string.dump ~= nil then bad[#bad+1] = 'string.dump' end\n"
	       "  local ok = pcall(require, '../sand')\n"
	       "  if ok then bad[#bad+1] = 'require ..' end\n"
	       "  ok = pcall(require, 'nonexistent')\n"
	       "  if ok then bad[#bad+1] = 'require nonexistent' end\n"
	       "  if #bad > 0 then return p:fail('error', table.concat(bad, ',')) end\n"
	       "  return p:ok('clean')\n"
	       " end }\n");
	char *o = run("sand", NULL, 1, 1000, NULL);
	CHECK(HAS(o, "\"detail\":\"clean\""));
	if (!HAS(o, "clean")) printf("  %s\n", o);
	free(o);

	script("loop", "return { protos = {'tls'}, check = function(p, a) local i = 0 while true do i = i + 1 end end }\n");
	int64_t t0 = now_ms();
	o = run("loop", NULL, 1, 300, NULL);
	int64_t dt = now_ms() - t0;
	CHECK(HAS(o, "\"detail\":\"check_timeout\"") && dt < 4000);
	free(o);

	/* a call asking for a long timeout is cut to what the job has left */
	int port;
	pid_t s = spawn_tcp(SRV_SILENT, &port);
	char args[100];
	script("slow", "return { protos = {'tls'}, args = {port={type='number'}}, check = function(p, a)\n"
		       "  local r = p:tls{host='example.com', ip='127.0.0.1', port=a.port, timeout=60000}\n"
		       "  local r2 = p:tls{host='example.com', ip='127.0.0.1', port=a.port, timeout=60000}\n"
		       "  return p:fail(r.class, 'first_' .. r.detail) end }\n");
	snprintf(args, sizeof args, "{\"port\":%d}", port);
	t0 = now_ms();
	o = run("slow", args, 1, 300, NULL);
	dt = now_ms() - t0;
	CHECK(dt < 5000 && (HAS(o, "check_timeout") || HAS(o, "first_no_reply")));
	free(o);
	reap(s);

	/* names that are not names, scripts that are not there, scripts that are not Lua text */
	o = run("../etc/passwd", NULL, 1, 1000, NULL);
	CHECK(HAS(o, "\"detail\":\"bad_check_name\""));
	free(o);
	o = run("missing", NULL, 1, 1000, NULL);
	CHECK(HAS(o, "\"detail\":\"script_not_found\""));
	free(o);
	script("syntax", "return {{{\n");
	o = run("syntax", NULL, 1, 1000, NULL);
	CHECK(HAS(o, "\"detail\":\"script_error\"") && HAS(o, "syntax.lua"));
	free(o);
	script("bytecode", "\x1b" "Lua....");
	o = run("bytecode", NULL, 1, 1000, NULL);
	CHECK(HAS(o, "script_error") && HAS(o, "bytecode"));
	free(o);
	script("notable", "return 5\n");
	o = run("notable", NULL, 1, 1000, NULL);
	CHECK(HAS(o, "script_error") && HAS(o, "did not return a table"));
	free(o);
	script("nocheck", "return { protos = {'tls'} }\n");
	o = run("nocheck", NULL, 1, 1000, NULL);
	CHECK(HAS(o, "\"detail\":\"no_check_function\""));
	free(o);

	/* require: lib/ of the search path, cached, a module can return nothing */
	char path[300];
	snprintf(path, sizeof path, "%s/lib", g_dir);
	mkdir(path, 0755);
	snprintf(path, sizeof path, "%s/lib/hello.lua", g_dir);
	FILE *f = fopen(path, "w");
	fputs("count = (count or 0) + 1\nreturn { name = ..., n = count }\n", f);
	fclose(f);
	script("usereq", "local a = require 'hello'\nlocal b = require 'hello'\n"
			 "return { protos = {'tls'}, check = function(p, x) return p:ok(a.name .. ':' .. tostring(a == b) .. ':' .. a.n) end }\n");
	o = run("usereq", NULL, 1, 1000, NULL);
	CHECK(HAS(o, "\"detail\":\"hello:true:1\""));
	free(o);
	unlink(path);
	snprintf(path, sizeof path, "%s/lib", g_dir);
	rmdir(path);
}

static void test_info_and_cli(void)
{
	sbuf out;
	sb_init(&out);
	check_info(&out);
	CHECK(HAS(out.p, "\"name\":\"generic\"") && HAS(out.p, "\"protos\":[\"tls\",\"quic\",\"http\"]"));
	CHECK(HAS(out.p, "\"name\":\"v\"") && HAS(out.p, "\"prepare\":true"));
	CHECK(HAS(out.p, "\"name\":\"syntax\"") && HAS(out.p, "\"error\":\"script_error\""));
	CHECK(HAS(out.p, "\"min_bytes\":{\"default\":65536,\"help\":\"bytes a download has to deliver (tls, confirm)\",\"type\":\"number\"}") && HAS(out.p, "\"required\":true"));
	sb_free(&out);

	char cmd[600], buf[8192];
	int port;
	pid_t s = spawn_tcp(SRV_HELLO, &port);
	snprintf(cmd, sizeof cmd,
		 "" ZPROBE " check --check generic --checks %s --checks checks --arg host=example.com --arg ip=127.0.0.1 --arg port=%d "
		 "--arg stage=screen --timeout 1500", g_dir, port);
	FILE *f = popen(cmd, "r");
	size_t n = fread(buf, 1, sizeof buf - 1, f);
	buf[n] = 0;
	int st = pclose(f);
	CHECK(WEXITSTATUS(st) == 0 && HAS(buf, "\"class\":\"ok\"") && HAS(buf, "server_hello"));
	reap(s);
	s = spawn_tcp(SRV_ALERT, &port);
	snprintf(cmd, sizeof cmd,
		 "" ZPROBE " check --check generic --checks checks --arg host=example.com --arg ip=127.0.0.1 --arg port=%d "
		 "--arg stage=screen --timeout 1500", port);
	f = popen(cmd, "r");
	n = fread(buf, 1, sizeof buf - 1, f);
	buf[n] = 0;
	st = pclose(f);
	CHECK(WEXITSTATUS(st) == 1 && HAS(buf, "\"class\":\"alert\""));
	reap(s);

	/* batch: nested args, parallel jobs, a hanging script does not hold the others */
	s = spawn_tcp(SRV_HELLO, &port);
	snprintf(cmd, sizeof cmd,
		 "printf '%%s\\n' "
		 "'{\"id\":\"a\",\"cmd\":\"check\",\"check\":\"v\",\"args\":{\"n\":3,\"prepared\":{\"nodes\":[\"r1\"]}}}' "
		 "'{\"id\":\"b\",\"cmd\":\"check\",\"check\":\"loop\",\"timeout\":200}' "
		 "'{\"id\":\"c\",\"cmd\":\"check\",\"check\":\"prims\",\"args\":{\"port\":%d,\"mode\":\"tls\"}}' "
		 "'{\"id\":\"d\",\"cmd\":\"tls\",\"host\":\"example.com\",\"ip\":\"127.0.0.1\",\"port\":%d}' "
		 "| " ZPROBE " batch --parallel 4 --checks %s", port, port, g_dir);
	f = popen(cmd, "r");
	n = fread(buf, 1, sizeof buf - 1, f);
	buf[n] = 0;
	pclose(f);
	CHECK(HAS(buf, "\"id\":\"a\"") && HAS(buf, "\"n\":3") && HAS(buf, "\"nodes\":[\"r1\"]"));
	CHECK(HAS(buf, "\"id\":\"b\"") && HAS(buf, "check_timeout"));
	CHECK(HAS(buf, "\"id\":\"c\"") && HAS(buf, "ok/server_hello"));
	CHECK(HAS(buf, "\"id\":\"d\"") && HAS(buf, "\"proto\":\"tls\""));
	reap(s);
	/* --parallel 1 still gives each check its own process, output stays one line per job */
	snprintf(cmd, sizeof cmd,
		 "printf '%%s\\n' '{\"id\":\"a\",\"cmd\":\"check\",\"check\":\"v\"}' '{\"id\":\"b\",\"cmd\":\"check\",\"check\":\"v\"}' "
		 "| " ZPROBE " batch --checks %s | wc -l", g_dir);
	f = popen(cmd, "r");
	n = fread(buf, 1, sizeof buf - 1, f);
	buf[n] = 0;
	pclose(f);
	CHECK(atoi(buf) == 2);
}

int main(void)
{
	signal(SIGPIPE, SIG_IGN);
	if (!mkdtemp(g_dir)) { perror("mkdtemp"); return 1; }
	check_add_dir(g_dir);
	check_add_dir("checks");
	CHECK(check_have_lua());
	test_primitives();
	test_verdicts_and_args();
	test_sandbox_and_limits();
	test_info_and_cli();
	char cmd[400];
	snprintf(cmd, sizeof cmd, "rm -rf %s", g_dir);
	if (system(cmd)) {}
	DONE();
}
