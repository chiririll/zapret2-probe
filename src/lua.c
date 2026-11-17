#define _GNU_SOURCE
/* Check scripts: what "works" means for a service is a Lua script, the transport stays in C.
 * One lua_State per job, created in the process that runs the job (a forked batch child, after priv_drop).
 * Scripts make plain blocking calls; the primitives are the existing probes, one each. */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <math.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include "check.h"

#define MAX_DIRS 16
static const char *g_dirs[MAX_DIRS];
static int g_ndirs;

void check_add_dir(const char *dir)
{
	if (g_ndirs < MAX_DIRS) g_dirs[g_ndirs++] = dir;
}

#ifndef WITH_LUA

bool check_have_lua(void) { return false; }

int run_check(const char *id, const probe_opts *o, const char *check, const char *phase, const char *args_json, sbuf *out)
{
	sb_puts(out, "{");
	if (id) { sb_puts(out, "\"id\":"); sb_jstr(out, id); sb_puts(out, ","); }
	sb_puts(out, "\"proto\":\"check\",\"check\":");
	sb_jstr(out, check ? check : "");
	sb_puts(out, ",\"repeat\":1,\"ok\":0,\"class\":\"error\",\"counts\":{\"error\":1},"
		     "\"results\":[{\"class\":\"error\",\"ms\":0,\"detail\":\"no_lua\"}]}");
	return 1;
}

void check_info(sbuf *out) { sb_puts(out, "[]"); }

#else

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "runner_lua.h"

#if LUA_VERSION_NUM >= 502
#define OBJLEN(L, i) ((int)lua_rawlen(L, i))
#else
#define OBJLEN(L, i) ((int)lua_objlen(L, i))
#endif

#define MAX_SCRIPT (256 * 1024)
#define MAX_STEPS 64
#define HARD_MAX_BODY (16 * 1024 * 1024)
#define MARGIN_MS 2000

bool check_have_lua(void) { return true; }

/* ---------- state of the running job (one job per process) ---------- */

typedef struct {
	const probe_opts *job;
	int64_t deadline;        /* this repeat */
	sbuf steps;
	int nsteps;
	bool have_verdict;
	result_class vcls;
	char vdetail[48];
	char vmsg[160];
} ctx_t;

static ctx_t *g_ctx;

/* ---------- finding scripts ---------- */

static bool name_ok(const char *n, bool dash)
{
	if (!*n || strlen(n) > 64) return false;
	for (; *n; n++)
		if (!isalnum((unsigned char)*n) && *n != '_' && !(dash && *n == '-')) return false;
	return true;
}

static void each_dir(const char **list, int *n, char *buf, size_t bsz)
{
	*n = 0;
	if (g_ndirs) {
		for (int i = 0; i < g_ndirs; i++) list[(*n)++] = g_dirs[i];
		return;
	}
	snprintf(buf, bsz, "%s", CHECK_DIRS);
	for (char *s = strtok(buf, ":"); s && *n < MAX_DIRS; s = strtok(NULL, ":")) list[(*n)++] = s;
}

static char *read_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	if (!f) return NULL;
	char *b = malloc(MAX_SCRIPT + 1);
	if (!b) { fclose(f); return NULL; }
	size_t n = fread(b, 1, MAX_SCRIPT + 1, f);
	fclose(f);
	if (n > MAX_SCRIPT) { free(b); return NULL; }
	b[n] = 0;
	*len = n;
	return b;
}

/* sub is "" or "lib"; the first directory that has NAME.lua wins */
static char *find_script(const char *sub, const char *name, size_t *len, char *found, size_t fsz)
{
	const char *dirs[MAX_DIRS];
	char dbuf[512];
	int nd;
	each_dir(dirs, &nd, dbuf, sizeof dbuf);
	for (int i = 0; i < nd; i++) {
		char path[1024];
		if (snprintf(path, sizeof path, "%s/%s%s%s.lua", dirs[i], sub, *sub ? "/" : "", name) >= (int)sizeof path) continue;
		char *b = read_file(path, len);
		if (b) { if (found) snprintf(found, fsz, "%.*s", (int)fsz - 1, path); return b; }
	}
	return NULL;
}

/* text chunks only: no precompiled bytecode from a script directory */
static int load_text(lua_State *L, const char *buf, size_t len, const char *chunkname)
{
	if (len && (unsigned char)buf[0] == 0x1b) {
		lua_pushstring(L, "bytecode is not accepted");
		return LUA_ERRSYNTAX;
	}
	return luaL_loadbuffer(L, buf, len, chunkname);
}

/* ---------- sandbox ---------- */

static void open_lib(lua_State *L, const char *name, lua_CFunction f)
{
#if LUA_VERSION_NUM >= 502
	luaL_requiref(L, name, f, 1);
	lua_pop(L, 1);
#else
	lua_pushcfunction(L, f);
	lua_pushstring(L, name);
	lua_call(L, 1, 0);
#endif
}

static int l_require(lua_State *L)
{
	const char *name = luaL_checkstring(L, 1);
	if (!name_ok(name, false)) return luaL_error(L, "bad module name");
	lua_getfield(L, LUA_REGISTRYINDEX, "zp_loaded");
	lua_getfield(L, -1, name);
	if (!lua_isnil(L, -1)) return 1;
	lua_pop(L, 1);
	size_t len;
	char *buf = find_script("lib", name, &len, NULL, 0);
	if (!buf) return luaL_error(L, "module '%s' not found", name);
	char cn[80];
	snprintf(cn, sizeof cn, "@lib/%s.lua", name);
	int rc = load_text(L, buf, len, cn);
	free(buf);
	if (rc) return lua_error(L);
	lua_pushstring(L, name);
	lua_call(L, 1, 1);
	if (lua_isnil(L, -1)) { lua_pop(L, 1); lua_pushboolean(L, 1); }
	lua_pushvalue(L, -1);
	lua_setfield(L, -3, name);        /* loaded[name] = result */
	return 1;
}

static const char *const removed[] = { "dofile", "loadfile", "load", "loadstring", "print", "module",
				       "newproxy", "getfenv", "setfenv", NULL };

static lua_State *new_state(void)
{
	lua_State *L = luaL_newstate();
	if (!L) return NULL;
	open_lib(L, "_G", luaopen_base);
	open_lib(L, LUA_TABLIBNAME, luaopen_table);
	open_lib(L, LUA_STRLIBNAME, luaopen_string);
	open_lib(L, LUA_MATHLIBNAME, luaopen_math);
	for (int i = 0; removed[i]; i++) { lua_pushnil(L); lua_setglobal(L, removed[i]); }
	lua_getglobal(L, "string");
	lua_pushnil(L);
	lua_setfield(L, -2, "dump");
	lua_pop(L, 1);
	lua_newtable(L);
	lua_setfield(L, LUA_REGISTRYINDEX, "zp_loaded");
	lua_pushcfunction(L, l_require);
	lua_setglobal(L, "require");
	return L;
}

/* ---------- JSON <-> Lua ---------- */

static void utf8_put(sbuf *b, unsigned cp)
{
	char t[5];
	int n;
	if (cp < 0x80) { t[0] = cp; n = 1; }
	else if (cp < 0x800) { t[0] = 0xc0 | (cp >> 6); t[1] = 0x80 | (cp & 63); n = 2; }
	else if (cp < 0x10000) { t[0] = 0xe0 | (cp >> 12); t[1] = 0x80 | ((cp >> 6) & 63); t[2] = 0x80 | (cp & 63); n = 3; }
	else { t[0] = 0xf0 | (cp >> 18); t[1] = 0x80 | ((cp >> 12) & 63); t[2] = 0x80 | ((cp >> 6) & 63); t[3] = 0x80 | (cp & 63); n = 4; }
	t[n] = 0;
	sb_puts(b, t);
}

static const char *jd_skip(const char *s) { while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++; return s; }

static const char *jd_string(const char *s, sbuf *b)
{
	for (s++; *s && *s != '"'; s++) {
		if (*s != '\\') { char t[2] = { *s, 0 }; sb_puts(b, t); continue; }
		s++;
		switch (*s) {
		case 'n': sb_puts(b, "\n"); break;
		case 't': sb_puts(b, "\t"); break;
		case 'r': sb_puts(b, "\r"); break;
		case 'b': sb_puts(b, "\b"); break;
		case 'f': sb_puts(b, "\f"); break;
		case 'u': {
			unsigned cp = 0;
			for (int i = 1; i <= 4; i++) {
				if (!isxdigit((unsigned char)s[i])) return NULL;
				cp = cp * 16 + (isdigit((unsigned char)s[i]) ? s[i] - '0' : (tolower((unsigned char)s[i]) - 'a' + 10));
			}
			s += 4;
			if (cp >= 0xd800 && cp < 0xdc00 && s[1] == '\\' && s[2] == 'u') {
				unsigned lo = 0;
				for (int i = 3; i <= 6; i++) {
					if (!isxdigit((unsigned char)s[i])) return NULL;
					lo = lo * 16 + (isdigit((unsigned char)s[i]) ? s[i] - '0' : (tolower((unsigned char)s[i]) - 'a' + 10));
				}
				if (lo >= 0xdc00 && lo < 0xe000) { cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00); s += 6; }
			}
			utf8_put(b, cp);
			break;
		}
		case 0: return NULL;
		default: { char t[2] = { *s, 0 }; sb_puts(b, t); }
		}
	}
	return *s == '"' ? s + 1 : NULL;
}

/* pushes the value; NULL if malformed. null becomes nil (in arrays it is skipped) */
static const char *jd_value(lua_State *L, const char *s, int depth)
{
	if (depth > 16 || !lua_checkstack(L, 4)) return NULL;
	s = jd_skip(s);
	if (*s == '"') {
		sbuf b;
		sb_init(&b);
		s = jd_string(s, &b);
		if (s) lua_pushlstring(L, b.p ? b.p : "", b.len);
		sb_free(&b);
		return s;
	}
	if (*s == '{') {
		lua_newtable(L);
		s = jd_skip(s + 1);
		if (*s == '}') return s + 1;
		for (;;) {
			s = jd_skip(s);
			if (*s != '"') return NULL;
			sbuf k;
			sb_init(&k);
			s = jd_string(s, &k);
			if (!s) { sb_free(&k); return NULL; }
			lua_pushlstring(L, k.p ? k.p : "", k.len);
			sb_free(&k);
			s = jd_skip(s);
			if (*s++ != ':') return NULL;
			if (!(s = jd_value(L, s, depth + 1))) return NULL;
			lua_settable(L, -3);        /* a nil value removes nothing and sets nothing */
			s = jd_skip(s);
			if (*s == ',') { s++; continue; }
			return *s == '}' ? s + 1 : NULL;
		}
	}
	if (*s == '[') {
		lua_newtable(L);
		int n = 0;
		s = jd_skip(s + 1);
		if (*s == ']') return s + 1;
		for (;;) {
			if (!(s = jd_value(L, s, depth + 1))) return NULL;
			if (lua_isnil(L, -1)) lua_pop(L, 1);
			else lua_rawseti(L, -2, ++n);
			s = jd_skip(s);
			if (*s == ',') { s++; continue; }
			return *s == ']' ? s + 1 : NULL;
		}
	}
	if (!strncmp(s, "true", 4)) { lua_pushboolean(L, 1); return s + 4; }
	if (!strncmp(s, "false", 5)) { lua_pushboolean(L, 0); return s + 5; }
	if (!strncmp(s, "null", 4)) { lua_pushnil(L); return s + 4; }
	char *e;
	double d = strtod(s, &e);
	if (e == s) return NULL;
	if (!memchr(s, '.', e - s) && !memchr(s, 'e', e - s) && !memchr(s, 'E', e - s) && fabs(d) < 9e15) lua_pushinteger(L, (lua_Integer)d);
	else lua_pushnumber(L, d);
	return e;
}

/* a JSON string with invalid UTF-8 would break the reader of our output: replace such bytes */
static void jstr_utf8(sbuf *b, const char *s, size_t n)
{
	sbuf t;
	sb_init(&t);
	for (size_t i = 0; i < n; ) {
		unsigned char c = s[i];
		int k = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
		bool ok = k && i + k <= n;
		for (int j = 1; ok && j < k; j++) if (((unsigned char)s[i + j] >> 6) != 2) ok = false;
		if (c == 0) ok = false;
		if (ok) { char tmp[5]; memcpy(tmp, s + i, k); tmp[k] = 0; sb_puts(&t, tmp); i += k; }
		else { sb_puts(&t, "?"); i++; }
	}
	sb_jstr(b, t.p ? t.p : "");
	sb_free(&t);
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static void lj_encode(lua_State *L, int idx, sbuf *b, int depth)
{
	if (idx < 0 && idx > LUA_REGISTRYINDEX) idx = lua_gettop(L) + idx + 1;
	switch (lua_type(L, idx)) {
	case LUA_TBOOLEAN: sb_puts(b, lua_toboolean(L, idx) ? "true" : "false"); break;
	case LUA_TNUMBER: {
		double d = lua_tonumber(L, idx);
		if (d != d || d > 1e300 || d < -1e300) sb_puts(b, "null");
		else if (d == floor(d) && fabs(d) < 9e15) sb_printf(b, "%lld", (long long)d);
		else sb_printf(b, "%.14g", d);
		break;
	}
	case LUA_TSTRING: { size_t n; const char *s = lua_tolstring(L, idx, &n); jstr_utf8(b, s, n); break; }
	case LUA_TTABLE: {
		if (depth > 8) { sb_puts(b, "null"); break; }
		int n = OBJLEN(L, idx), cnt = 0;
		lua_pushnil(L);
		while (lua_next(L, idx)) { cnt++; lua_pop(L, 1); }
		if (cnt == 0 || (n > 0 && cnt == n)) {
			sb_puts(b, "[");
			for (int i = 1; i <= n; i++) {
				if (i > 1) sb_puts(b, ",");
				lua_rawgeti(L, idx, i);
				lj_encode(L, -1, b, depth + 1);
				lua_pop(L, 1);
			}
			sb_puts(b, "]");
			break;
		}
		/* string keys in sorted order: the same output under every Lua */
		char **keys = calloc(cnt ? cnt : 1, sizeof *keys);
		int nk = 0;
		lua_pushnil(L);
		while (lua_next(L, idx)) {
			if (lua_type(L, -2) == LUA_TSTRING && keys) keys[nk++] = strdup(lua_tostring(L, -2));
			lua_pop(L, 1);
		}
		qsort(keys, nk, sizeof *keys, cmp_str);
		sb_puts(b, "{");
		for (int i = 0; i < nk; i++) {
			if (i) sb_puts(b, ",");
			jstr_utf8(b, keys[i], strlen(keys[i]));
			sb_puts(b, ":");
			lua_getfield(L, idx, keys[i]);
			lj_encode(L, -1, b, depth + 1);
			lua_pop(L, 1);
			free(keys[i]);
		}
		free(keys);
		sb_puts(b, "}");
		break;
	}
	default: sb_puts(b, "null");
	}
}

/* ---------- primitives ---------- */

static void step_add(const char *prim, const char *host, const char *ip, const presult *r)
{
	if (!g_ctx || g_ctx->nsteps >= MAX_STEPS) return;
	sbuf *b = &g_ctx->steps;
	if (g_ctx->nsteps++) sb_puts(b, ",");
	sb_printf(b, "{\"p\":\"%s\",\"host\":", prim);
	jstr_utf8(b, host ? host : "", host ? strlen(host) : 0);
	if (ip && ip[0]) { sb_puts(b, ",\"ip\":"); sb_jstr(b, ip); }
	sb_printf(b, ",\"class\":\"%s\",\"ms\":%d", class_name(r->cls), r->ms);
	if (r->detail[0]) { sb_puts(b, ",\"detail\":"); sb_jstr(b, r->detail); }
	if (r->bytes) sb_printf(b, ",\"bytes\":%d", r->bytes);
	if (r->status) sb_printf(b, ",\"status\":%d", r->status);
	sb_puts(b, "}");
}

typedef struct {
	probe_opts o;
	char host[256], ip[64], path[4096], tpl[256], server[64], ref[64], method[16];
	sbuf hdrs;
	const char *body;        /* points into the Lua argument table */
	size_t body_len;
	const uint8_t *payload;  /* udp */
	size_t payload_len;
	int wait_ms;
	int port;
} prim_t;

static bool get_str(lua_State *L, int t, const char *k, char *dst, size_t n)
{
	lua_getfield(L, t, k);
	bool ok = lua_type(L, -1) == LUA_TSTRING;
	if (ok) snprintf(dst, n, "%s", lua_tostring(L, -1));
	lua_pop(L, 1);
	return ok;
}

static long get_int(lua_State *L, int t, const char *k, long def)
{
	lua_getfield(L, t, k);
	long v = lua_type(L, -1) == LUA_TNUMBER ? (long)lua_tonumber(L, -1) : def;
	lua_pop(L, 1);
	return v;
}

/* https://host[:port]/path */
static bool split_url(const char *url, char *host, size_t hn, int *port, char *path, size_t pn)
{
	if (strncasecmp(url, "https://", 8)) return false;
	url += 8;
	size_t i = 0;
	while (*url && *url != '/' && *url != ':' && *url != '?' && i + 1 < hn) host[i++] = *url++;
	host[i] = 0;
	if (*url == ':') { *port = atoi(url + 1); while (*url && *url != '/' && *url != '?') url++; }
	if (!*url) snprintf(path, pn, "/");
	else if (*url == '?') snprintf(path, pn, "/%s", url);
	else snprintf(path, pn, "%s", url);
	return i > 0;
}

static bool token_ok(const char *s, bool name)
{
	if (!*s) return false;
	for (; *s; s++) {
		unsigned char c = *s;
		if (name ? !(isalnum(c) || c == '-' || c == '_') : (c == '\r' || c == '\n' || c == 0)) return false;
	}
	return true;
}

/* reads the common fields of the call's table (argument 2, may be absent). Returns an error message or NULL. */
static const char *prim_args(lua_State *L, const char *prim, prim_t *p)
{
	memset(p, 0, sizeof *p);
	sb_init(&p->hdrs);
	const probe_opts *job = g_ctx->job;
	p->o = *job;
	int t = lua_istable(L, 2) ? 2 : 0;
	int dport = !strcmp(prim, "http") ? 80 : !strcmp(prim, "dns") ? 53 : 443;
	if (lua_isstring(L, 2) && !t) {
		snprintf(p->host, sizeof p->host, "%s", lua_tostring(L, 2));      /* p:tls("host"), p:dns("host") */
	}
	if (t) {
		char url[2048] = "";
		get_str(L, t, "host", p->host, sizeof p->host);
		get_str(L, t, "ip", p->ip, sizeof p->ip);
		get_str(L, t, "path", p->path, sizeof p->path);
		if (!strcmp(prim, "fetch") && get_str(L, t, "url", url, sizeof url)) {
			int up = 0;
			if (!split_url(url, p->host, sizeof p->host, &up, p->path, sizeof p->path)) return "bad_url";
			if (up) p->port = up;
		}
		get_str(L, t, "template", p->tpl, sizeof p->tpl);
		get_str(L, t, "server", p->server, sizeof p->server);
		get_str(L, t, "ref", p->ref, sizeof p->ref);
		if (get_str(L, t, "method", p->method, sizeof p->method)) {
			for (char *c = p->method; *c; c++) if (!isupper((unsigned char)*c)) return "bad_method";
		}
		long port = get_int(L, t, "port", 0);
		if (port > 0 && port < 65536) p->port = (int)port;
		long to = get_int(L, t, "timeout", 0);
		if (to > 0) p->o.timeout_ms = (int)to;
		long fam = get_int(L, t, "family", 0);
		if (fam == 4 || fam == 6) p->o.family = (int)fam;
		p->wait_ms = (int)get_int(L, t, "wait_ms", 1000);
		long mb = get_int(L, t, "max_body", (long)job->max_body);
		p->o.max_body = mb < 0 ? 0 : mb > HARD_MAX_BODY ? HARD_MAX_BODY : (size_t)mb;
		p->o.min_bytes = (int)get_int(L, t, "min_bytes", 0);
		lua_getfield(L, t, "stop");
		if (lua_type(L, -1) == LUA_TSTRING) p->o.stop_headers = !strcmp(lua_tostring(L, -1), "headers");
		lua_pop(L, 1);
		lua_getfield(L, t, "body");
		if (lua_type(L, -1) == LUA_TSTRING) p->body = lua_tolstring(L, -1, &p->body_len);
		lua_pop(L, 1);                     /* the string stays referenced by the table */
		lua_getfield(L, t, "payload");
		if (lua_type(L, -1) == LUA_TSTRING) p->payload = (const uint8_t *)lua_tolstring(L, -1, &p->payload_len);
		lua_pop(L, 1);
		lua_getfield(L, t, "headers");
		if (lua_istable(L, -1)) {
			lua_pushnil(L);
			while (lua_next(L, -2)) {
				if (lua_type(L, -2) == LUA_TSTRING && lua_type(L, -1) != LUA_TTABLE) {
					const char *k = lua_tostring(L, -2);
					lua_pushvalue(L, -1);
					const char *v = lua_tostring(L, -1);
					if (!v || !token_ok(k, true) || !token_ok(v, false)) { lua_pop(L, 3); return "bad_header"; }
					sb_printf(&p->hdrs, "%s: %s\r\n", k, v);
					lua_pop(L, 1);
				}
				lua_pop(L, 1);
			}
		}
		lua_pop(L, 1);
	}
	if (!p->host[0]) return "no_host";
	if (!p->port) p->port = dport;
	if (!p->path[0]) snprintf(p->path, sizeof p->path, "/");
	/* the job's remaining time caps every call */
	int64_t left = g_ctx->deadline - now_ms();
	if (left <= 0) return "check_timeout";
	if (p->o.timeout_ms > left) p->o.timeout_ms = (int)left;
	if (p->o.timeout_ms < 50) p->o.timeout_ms = 50;
	p->o.host = p->host;
	p->o.ip = p->ip[0] ? p->ip : NULL;
	p->o.port = p->port;
	p->o.path = p->path;
	p->o.template_path = p->tpl[0] ? p->tpl : NULL;
	p->o.server = p->server[0] ? p->server : NULL;
	p->o.ref = p->ref[0] ? p->ref : NULL;
	if (!strcmp(prim, "fetch")) {
		p->o.once = true;
		p->o.method = p->method[0] ? p->method : NULL;
		p->o.hdrs = p->hdrs.len ? p->hdrs.p : NULL;
		p->o.body = (const uint8_t *)p->body;
		p->o.body_len = p->body_len;
	}
	return NULL;
}

static void push_headers(lua_State *L, const char *h, size_t n)
{
	lua_newtable(L);
	const char *end = h + n;
	const char *l = memchr(h, '\n', n);
	while (l && l + 1 < end) {
		l++;
		const char *e = memchr(l, '\n', end - l);
		if (!e) break;
		const char *colon = memchr(l, ':', e - l);
		if (colon && colon > l) {
			char key[128];
			size_t kl = (size_t)(colon - l) < sizeof key - 1 ? (size_t)(colon - l) : sizeof key - 1;
			for (size_t i = 0; i < kl; i++) key[i] = tolower((unsigned char)l[i]);
			key[kl] = 0;
			const char *v = colon + 1, *ve = e;
			while (v < ve && (*v == ' ' || *v == '\t')) v++;
			while (ve > v && (ve[-1] == '\r' || ve[-1] == ' ')) ve--;
			lua_getfield(L, -1, key);
			if (lua_type(L, -1) == LUA_TSTRING) {
				lua_pushstring(L, ", ");
				lua_pushlstring(L, v, ve - v);
				lua_concat(L, 3);
			} else {
				lua_pop(L, 1);
				lua_pushlstring(L, v, ve - v);
			}
			lua_setfield(L, -2, key);
		}
		l = e;
	}
}

/* UDP: one datagram out, collect replies for wait_ms */
static void probe_udp(const prim_t *p, const struct sockaddr_storage *ss, socklen_t sl, presult *r, lua_State *L)
{
	memset(r, 0, sizeof *r);
	int fd = net_socket(ss->ss_family, SOCK_DGRAM, p->o.mark);
	if (fd < 0) { r->cls = RC_ERROR; set_detail(r, "socket_%s", strerror(errno)); return; }
	if (connect(fd, (const struct sockaddr *)ss, sl) < 0) { net_conn_fail(r, errno); close(fd); return; }
	int64_t t0 = now_ms(), dl = t0 + p->wait_ms;
	if (dl > g_ctx->deadline) dl = g_ctx->deadline;
	if (p->payload_len && send(fd, p->payload, p->payload_len, 0) < 0) {
		r->cls = errno == ECONNREFUSED ? RC_UNREACHABLE : RC_ERROR;
		set_detail(r, "send_%s", strerror(errno));
		close(fd);
		return;
	}
	lua_newtable(L);                     /* replies, left on the stack for the caller */
	int n = 0;
	uint8_t buf[2048];
	for (;;) {
		ssize_t k = net_read(fd, buf, sizeof buf, dl);
		if (k >= 0) {
			lua_pushlstring(L, (const char *)buf, k);
			lua_rawseti(L, -2, ++n);
			r->bytes += (int)k;
			if (n >= 16) break;
			continue;
		}
		if (errno != ETIMEDOUT && !n) { r->cls = RC_UNREACHABLE; set_detail(r, "icmp_%s", strerror(errno)); }
		break;
	}
	if (!r->cls && !n) { r->cls = RC_TIMEOUT; set_detail(r, "no_reply"); }
	else if (n) { r->cls = RC_OK; set_detail(r, "replies_%d", n); }
	r->ms = (int)(now_ms() - t0);
	close(fd);
}

/* p:KIND{...}: runs a probe and returns its result table */
static int prim_run(lua_State *L, const char *kind)
{
	prim_t p;
	presult r;
	char ipstr[64] = "";
	bool udp = !strcmp(kind, "udp"), dns = !strcmp(kind, "dns");
	const char *err = prim_args(L, kind, &p);
	if (err) { sb_free(&p.hdrs); return luaL_error(L, "%s", err); }
	memset(&r, 0, sizeof r);
	int udp_replies = 0;
	struct sockaddr_storage ss;
	socklen_t sl = 0;
	if (!dns) {
		int st = (udp || !strcmp(kind, "quic")) ? SOCK_DGRAM : SOCK_STREAM;
		if (net_resolve(p.host, p.o.ip, p.o.family, p.port, st, &ss, &sl) == 0)
			getnameinfo((struct sockaddr *)&ss, sl, ipstr, sizeof ipstr, NULL, 0, NI_NUMERICHOST);
		else { r.cls = RC_UNREACHABLE; set_detail(&r, "resolve_failed"); }
	}
	int base = lua_gettop(L);
	if (r.cls == RC_OK && !r.detail[0]) {
		if (!strcmp(kind, "tls")) probe_tls(&p.o, &ss, sl, &r);
		else if (!strcmp(kind, "quic")) probe_quic(&p.o, &ss, sl, &r);
		else if (!strcmp(kind, "http")) probe_http(&p.o, &ss, sl, &r);
		else if (!strcmp(kind, "fetch")) probe_fetch(&p.o, &ss, sl, &r);
		else if (udp) { probe_udp(&p, &ss, sl, &r, L); udp_replies = lua_gettop(L) > base; }
		else probe_dns(&p.o, &r);
	}
	step_add(kind, p.host, ipstr, &r);

	lua_newtable(L);
	lua_pushstring(L, class_name(r.cls)); lua_setfield(L, -2, "class");
	lua_pushstring(L, r.detail); lua_setfield(L, -2, "detail");
	lua_pushinteger(L, r.ms); lua_setfield(L, -2, "ms");
	lua_pushstring(L, ipstr); lua_setfield(L, -2, "ip");
	if (r.status) { lua_pushinteger(L, r.status); lua_setfield(L, -2, "status"); }
	if (r.bytes || !strcmp(kind, "fetch")) { lua_pushinteger(L, r.bytes); lua_setfield(L, -2, "bytes"); }
	if (!strcmp(kind, "fetch")) {
		lua_pushinteger(L, r.hs_ms); lua_setfield(L, -2, "hs_ms");
		if (r.rhdr) push_headers(L, r.rhdr, r.rhdr_len); else lua_newtable(L);
		lua_setfield(L, -2, "headers");
		if (r.rbody) { lua_pushlstring(L, r.rbody, r.rbody_len); lua_setfield(L, -2, "body"); }
	}
	if (dns) {
		lua_newtable(L);
		char tmp[256];
		snprintf(tmp, sizeof tmp, "%s", r.info);
		int n = 0;
		for (char *s = strtok(tmp, " "); s; s = strtok(NULL, " ")) { lua_pushstring(L, s); lua_rawseti(L, -2, ++n); }
		lua_setfield(L, -2, "answers");
	}
	if (udp_replies) { lua_pushvalue(L, base + 1); lua_setfield(L, -2, "replies"); }
	free(r.rhdr); free(r.rbody); free(r.dump);
	sb_free(&p.hdrs);
	return 1;
}

#define PRIM(name) static int p_##name(lua_State *L) { return prim_run(L, #name); }
PRIM(dns) PRIM(tls) PRIM(quic) PRIM(fetch) PRIM(http) PRIM(udp)

static int p_report(lua_State *L)
{
	const char *k = luaL_checkstring(L, 2);
	luaL_checkany(L, 3);
	lua_getfield(L, LUA_REGISTRYINDEX, "zp_data");
	lua_pushvalue(L, 3);
	lua_setfield(L, -2, k);
	return 0;
}

static int verdict(lua_State *L, result_class c, const char *detail)
{
	g_ctx->have_verdict = true;
	g_ctx->vcls = c;
	snprintf(g_ctx->vdetail, sizeof g_ctx->vdetail, "%s", detail ? detail : "");
	lua_newtable(L);
	lua_pushboolean(L, 1);
	lua_setfield(L, -2, "zp_verdict");
	return 1;
}

static int p_ok(lua_State *L) { return verdict(L, RC_OK, luaL_optstring(L, 2, "")); }
static int p_inconclusive(lua_State *L) { return verdict(L, RC_INCONCLUSIVE, luaL_optstring(L, 2, "")); }

static int p_fail(lua_State *L)
{
	const char *cn = luaL_checkstring(L, 2);
	result_class c = RC_ERROR;
	for (int i = 1; i < RC_COUNT; i++) if (i != RC_INCONCLUSIVE && !strcmp(class_name(i), cn)) c = i;
	return verdict(L, c, luaL_optstring(L, 3, ""));
}

static const luaL_Reg prims[] = {
	{ "dns", p_dns }, { "tls", p_tls }, { "quic", p_quic }, { "fetch", p_fetch }, { "http", p_http },
	{ "udp", p_udp }, { "report", p_report }, { "ok", p_ok }, { "fail", p_fail },
	{ "inconclusive", p_inconclusive }, { NULL, NULL }
};

static void push_p(lua_State *L)
{
	lua_newtable(L);                      /* p */
	lua_newtable(L);                      /* metatable */
	lua_newtable(L);                      /* __index = methods */
	for (const luaL_Reg *r = prims; r->name; r++) { lua_pushcfunction(L, r->func); lua_setfield(L, -2, r->name); }
	lua_setfield(L, -2, "__index");
	lua_setmetatable(L, -2);
}

/* ---------- limits ---------- */

static void hook(lua_State *L, lua_Debug *ar)
{
	if (g_ctx && now_ms() > g_ctx->deadline + 500) luaL_error(L, "check_timeout");
}

static char g_alarm_msg[512];
static size_t g_alarm_len;

static void on_alarm(int sig)
{
	ssize_t w = write(1, g_alarm_msg, g_alarm_len);
	(void)w;
	_exit(3);
}

/* ---------- running a job ---------- */

static int cmp_int(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }

typedef struct {
	result_class cls;
	int ms;
	char detail[48];
	char msg[160];
	sbuf steps, data;
	bool has_data;
} rep_t;

static void error_result(rep_t *r, const char *detail, const char *msg)
{
	r->cls = RC_ERROR;
	snprintf(r->detail, sizeof r->detail, "%s", detail);
	if (msg) snprintf(r->msg, sizeof r->msg, "%s", msg);
}

static void emit(sbuf *out, const char *id, const char *check, const char *phase, rep_t *res, int rep)
{
	int counts[RC_COUNT] = { 0 };
	int *ms = calloc(rep, sizeof *ms), nms = 0;
	for (int i = 0; i < rep; i++) { counts[res[i].cls]++; if (res[i].cls == RC_OK) ms[nms++] = res[i].ms; }
	result_class best = RC_OK;
	if (counts[RC_OK] != rep) {
		int top = -1;
		for (int c = 0; c < RC_COUNT; c++) if (c != RC_OK && counts[c] > top) { top = counts[c]; best = c; }
	}
	qsort(ms, nms, sizeof *ms, cmp_int);
	sb_puts(out, "{");
	if (id) { sb_puts(out, "\"id\":"); sb_jstr(out, id); sb_puts(out, ","); }
	sb_puts(out, "\"proto\":\"check\",\"check\":");
	sb_jstr(out, check);
	sb_printf(out, ",\"phase\":\"%s\",\"repeat\":%d,\"ok\":%d,\"class\":\"%s\",\"counts\":{", phase, rep, counts[RC_OK], class_name(best));
	bool first = true;
	for (int c = 0; c < RC_COUNT; c++)
		if (counts[c]) { sb_printf(out, "%s\"%s\":%d", first ? "" : ",", class_name(c), counts[c]); first = false; }
	sb_puts(out, "}");
	if (nms) sb_printf(out, ",\"median_ms\":%d", ms[nms / 2]);
	sb_puts(out, ",\"results\":[");
	for (int i = 0; i < rep; i++) {
		sb_printf(out, "%s{\"class\":\"%s\",\"ms\":%d", i ? "," : "", class_name(res[i].cls), res[i].ms);
		if (res[i].detail[0]) { sb_puts(out, ",\"detail\":"); sb_jstr(out, res[i].detail); }
		if (res[i].msg[0]) { sb_puts(out, ",\"message\":"); jstr_utf8(out, res[i].msg, strlen(res[i].msg)); }
		sb_puts(out, ",\"steps\":[");
		if (res[i].steps.p) sb_puts(out, res[i].steps.p);
		sb_puts(out, "]");
		if (res[i].has_data) { sb_puts(out, ",\"data\":"); sb_puts(out, res[i].data.p); }
		sb_puts(out, "}");
	}
	sb_puts(out, "]}");
	free(ms);
}

/* loads NAME.lua and runs it; leaves the script's table on the stack. Returns an error detail or NULL. */
static const char *load_script(lua_State *L, const char *name, char *msg, size_t msz)
{
	size_t len;
	char path[512];
	if (!name_ok(name, true)) return "bad_check_name";
	char *buf = find_script("", name, &len, path, sizeof path);
	if (!buf) return "script_not_found";
	char cn[80];
	snprintf(cn, sizeof cn, "@%s.lua", name);
	int rc = load_text(L, buf, len, cn);
	free(buf);
	if (rc == 0) rc = lua_pcall(L, 0, 1, 0);
	if (rc) {
		snprintf(msg, msz, "%s", lua_tostring(L, -1));
		lua_pop(L, 1);
		return "script_error";
	}
	if (!lua_istable(L, -1)) { lua_pop(L, 1); snprintf(msg, msz, "script did not return a table"); return "script_error"; }
	return NULL;
}

/* script table at the top of the stack stays there; builds the normalized argument table into the registry */
static const char *setup_args(lua_State *L, int script_ref, const char *args_json, int *args_ref,
			      char *detail, size_t dsz, char *msg, size_t msz)
{
	int top = lua_gettop(L);
	if (args_json && *args_json) {
		const char *e = jd_value(L, args_json, 0);
		if (!e || !lua_istable(L, -1)) { lua_settop(L, top); return "bad_args"; }
	} else lua_newtable(L);
	int raw = lua_gettop(L);
	if (luaL_loadbuffer(L, RUNNER_LUA, sizeof RUNNER_LUA - 1, "=runner") || lua_pcall(L, 0, 1, 0)) {
		snprintf(msg, msz, "%s", lua_tostring(L, -1));
		lua_settop(L, top);
		return "runner_error";
	}
	int runner = lua_gettop(L);
	lua_rawgeti(L, LUA_REGISTRYINDEX, script_ref);
	int sc = lua_gettop(L);
	lua_pushvalue(L, runner);
	lua_getfield(L, sc, "args");
	lua_getfield(L, sc, "protos");
	if (!lua_istable(L, -1)) { lua_pop(L, 1); lua_pushnil(L); }
	lua_pushvalue(L, raw);
	if (lua_pcall(L, 3, 2, 0)) {
		snprintf(msg, msz, "%s", lua_tostring(L, -1));
		lua_settop(L, top);
		return "runner_error";
	}
	if (lua_isnil(L, -2)) {
		snprintf(detail, dsz, "%s", lua_tostring(L, -1) ? lua_tostring(L, -1) : "bad_args");
		lua_settop(L, top);
		return "bad_args";
	}
	lua_pop(L, 1);
	*args_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	lua_settop(L, top);
	return NULL;
}

int run_check(const char *id, const probe_opts *o, const char *check, const char *phase, const char *args_json, sbuf *out)
{
	bool prepare = phase && !strcmp(phase, "prepare");
	int rep = prepare ? 1 : (o->repeat < 1 ? 1 : o->repeat > 100 ? 100 : o->repeat);
	rep_t *res = calloc(rep, sizeof *res);
	probe_opts job = *o;
	if (!job.max_body) job.max_body = 256 * 1024;
	ctx_t ctx;
	memset(&ctx, 0, sizeof ctx);
	ctx.job = &job;
	sb_init(&ctx.steps);
	g_ctx = &ctx;

	/* a backstop for anything that blocks outside our own deadlines (name resolution, a stuck library call) */
	int total_s = (int)(((int64_t)rep * (job.timeout_ms + MARGIN_MS) + (int64_t)job.pace_ms * rep) / 1000) + 2;
	{
		sbuf m;
		sb_init(&m);
		sb_puts(&m, "{");
		if (id) { sb_puts(&m, "\"id\":"); sb_jstr(&m, id); sb_puts(&m, ","); }
		sb_puts(&m, "\"proto\":\"check\",\"check\":");
		sb_jstr(&m, check);
		sb_puts(&m, ",\"repeat\":1,\"ok\":0,\"class\":\"error\",\"counts\":{\"error\":1},"
			    "\"results\":[{\"class\":\"error\",\"ms\":0,\"detail\":\"check_timeout\",\"steps\":[]}]}\n");
		g_alarm_len = m.len < sizeof g_alarm_msg ? m.len : 0;
		if (g_alarm_len) { memcpy(g_alarm_msg, m.p, g_alarm_len); signal(SIGALRM, on_alarm); alarm(total_s); }
		sb_free(&m);
	}

	char msg[160] = "", detail[48] = "";
	const char *fail = NULL;
	const char *fn = prepare ? "prepare" : "check";
	bool has_fn = false;
	int args_ref = LUA_NOREF, script_ref = LUA_NOREF;
	lua_State *L = new_state();
	if (!L) fail = "lua_state";
	else if (!(fail = load_script(L, check, msg, sizeof msg))) {
		script_ref = luaL_ref(L, LUA_REGISTRYINDEX);
		lua_rawgeti(L, LUA_REGISTRYINDEX, script_ref);
		lua_getfield(L, -1, fn);
		has_fn = lua_isfunction(L, -1);
		lua_settop(L, 0);
		if (!has_fn && !prepare) fail = "no_check_function";
		else if (has_fn) fail = setup_args(L, script_ref, args_json, &args_ref, detail, sizeof detail, msg, sizeof msg);
	}
	if (fail) {
		for (int i = 0; i < rep; i++) error_result(&res[i], detail[0] ? detail : fail, msg[0] ? msg : NULL);
	} else if (!has_fn) {
		res[0].cls = RC_OK;
		snprintf(res[0].detail, sizeof res[0].detail, "no_prepare");
	} else {
		lua_sethook(L, hook, LUA_MASKCOUNT, 10000);
		for (int i = 0; i < rep; i++) {
			rep_t *r = &res[i];
			int64_t t0 = now_ms();
			ctx.deadline = t0 + job.timeout_ms + MARGIN_MS;
			ctx.have_verdict = false;
			ctx.nsteps = 0;
			sb_free(&ctx.steps);
			lua_newtable(L);
			lua_setfield(L, LUA_REGISTRYINDEX, "zp_data");
			lua_gc(L, LUA_GCCOLLECT, 0);
			lua_rawgeti(L, LUA_REGISTRYINDEX, script_ref);
			lua_getfield(L, -1, fn);
			push_p(L);
			lua_rawgeti(L, LUA_REGISTRYINDEX, args_ref);
			if (lua_pcall(L, 2, 1, 0)) {
				const char *m = lua_tostring(L, -1);
				if (m && strstr(m, "check_timeout")) error_result(r, "check_timeout", NULL);
				else error_result(r, "script_error", m ? m : "?");
			} else if (ctx.have_verdict) {
				r->cls = ctx.vcls;
				snprintf(r->detail, sizeof r->detail, "%s", ctx.vdetail);
			} else error_result(r, "no_verdict", NULL);
			lua_settop(L, 0);
			r->ms = (int)(now_ms() - t0);
			if (ctx.steps.p) { r->steps = ctx.steps; sb_init(&ctx.steps); }
			lua_getfield(L, LUA_REGISTRYINDEX, "zp_data");
			lua_pushnil(L);
			if (lua_next(L, -2)) {
				lua_pop(L, 2);
				sb_init(&r->data);
				lj_encode(L, -1, &r->data, 0);
				r->has_data = true;
			}
			lua_settop(L, 0);
			if (i + 1 < rep && job.pace_ms > 0) usleep(job.pace_ms * 1000);
		}
	}
	emit(out, id, check, prepare ? "prepare" : "check", res, rep);
	int bad = 0;
	for (int i = 0; i < rep; i++) {
		if (res[i].cls != RC_OK) bad++;
		sb_free(&res[i].steps);
		if (res[i].has_data) sb_free(&res[i].data);
	}
	free(res);
	sb_free(&ctx.steps);
	if (L) lua_close(L);
	alarm(0);
	g_ctx = NULL;
	return bad;
}

/* ---------- check-info ---------- */

static void info_one(sbuf *out, const char *name, bool *first)
{
	lua_State *L = new_state();
	char msg[160] = "";
	if (!L) return;
	const char *err = load_script(L, name, msg, sizeof msg);
	if (!*first) sb_puts(out, ",");
	*first = false;
	sb_puts(out, "{\"name\":");
	sb_jstr(out, name);
	if (err) {
		sb_printf(out, ",\"error\":\"%s\"", err);
		if (msg[0]) { sb_puts(out, ",\"message\":"); jstr_utf8(out, msg, strlen(msg)); }
	} else {
		lua_getfield(L, -1, "title");
		if (lua_type(L, -1) == LUA_TSTRING) { sb_puts(out, ",\"title\":"); lj_encode(L, -1, out, 0); }
		lua_pop(L, 1);
		lua_getfield(L, -1, "protos");
		sb_puts(out, ",\"protos\":");
		if (lua_istable(L, -1)) lj_encode(L, -1, out, 0); else sb_puts(out, "[]");
		lua_pop(L, 1);
		lua_getfield(L, -1, "args");
		sb_puts(out, ",\"args\":");
		if (lua_istable(L, -1)) { sbuf t; sb_init(&t); lj_encode(L, -1, &t, 0); sb_puts(out, t.p && t.p[0] == '{' ? t.p : "{}"); sb_free(&t); }
		else sb_puts(out, "{}");
		lua_pop(L, 1);
		lua_getfield(L, -1, "prepare");
		sb_printf(out, ",\"prepare\":%s", lua_isfunction(L, -1) ? "true" : "false");
		lua_pop(L, 1);
	}
	sb_puts(out, "}");
	lua_close(L);
}

void check_info(sbuf *out)
{
	const char *dirs[MAX_DIRS];
	char dbuf[512];
	int nd;
	char seen[256][68];
	int nseen = 0;
	bool first = true;
	each_dir(dirs, &nd, dbuf, sizeof dbuf);
	sb_puts(out, "[");
	for (int i = 0; i < nd; i++) {
		DIR *d = opendir(dirs[i]);
		if (!d) continue;
		struct dirent *e;
		while ((e = readdir(d))) {
			size_t l = strlen(e->d_name);
			if (l < 5 || strcmp(e->d_name + l - 4, ".lua")) continue;
			char name[68];
			snprintf(name, sizeof name, "%.*s", (int)(l - 4 > 64 ? 64 : l - 4), e->d_name);
			if (!name_ok(name, true)) continue;
			bool dup = false;
			for (int k = 0; k < nseen; k++) if (!strcmp(seen[k], name)) dup = true;
			if (dup || nseen >= 256) continue;
			snprintf(seen[nseen++], sizeof seen[0], "%s", name);
			info_one(out, name, &first);
		}
		closedir(d);
	}
	sb_puts(out, "]");
}

#endif
