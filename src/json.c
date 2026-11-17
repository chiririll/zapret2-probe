#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "json.h"

void sb_init(sbuf *b) { b->p = NULL; b->len = b->cap = 0; }
void sb_free(sbuf *b) { free(b->p); sb_init(b); }

static void sb_reserve(sbuf *b, size_t add)
{
	if (b->len + add + 1 <= b->cap) return;
	size_t nc = b->cap ? b->cap : 256;
	while (nc < b->len + add + 1) nc *= 2;
	char *np = realloc(b->p, nc);
	if (!np) abort();
	b->p = np; b->cap = nc;
}

void sb_puts(sbuf *b, const char *s)
{
	size_t l = strlen(s);
	sb_reserve(b, l);
	memcpy(b->p + b->len, s, l + 1);
	b->len += l;
}

void sb_printf(sbuf *b, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (n < 0) return;
	sb_reserve(b, n);
	va_start(ap, fmt);
	vsnprintf(b->p + b->len, n + 1, fmt, ap);
	va_end(ap);
	b->len += n;
}

void sb_jstr(sbuf *b, const char *s)
{
	sb_puts(b, "\"");
	for (; s && *s; s++) {
		unsigned char c = *s;
		switch (c) {
		case '"': sb_puts(b, "\\\""); break;
		case '\\': sb_puts(b, "\\\\"); break;
		case '\n': sb_puts(b, "\\n"); break;
		case '\r': sb_puts(b, "\\r"); break;
		case '\t': sb_puts(b, "\\t"); break;
		default:
			if (c < 0x20) sb_printf(b, "\\u%04x", c);
			else sb_printf(b, "%c", c);
		}
	}
	sb_puts(b, "\"");
}

static const char *ws(const char *s) { while (isspace((unsigned char)*s)) s++; return s; }

static const char *parse_str(const char *s, char *out, size_t osz)
{
	size_t o = 0;
	if (*s++ != '"') return NULL;
	while (*s && *s != '"') {
		char c = *s++;
		if (c == '\\') {
			c = *s++;
			switch (c) {
			case 'n': c = '\n'; break;
			case 't': c = '\t'; break;
			case 'r': c = '\r'; break;
			case 'u': if (strlen(s) < 4) return NULL; s += 4; c = '?'; break;
			case 0: return NULL;
			default: break; /* \" \\ \/ */
			}
		}
		if (o + 1 < osz) out[o++] = c;
	}
	if (*s != '"') return NULL;
	out[o] = 0;
	return s + 1;
}

/* s points at a value; returns the first char after it, NULL if malformed or too deep */
static const char *skip_value_d(const char *s, int depth)
{
	if (depth > 24) return NULL;
	s = ws(s);
	if (*s == '"') {
		for (s++; *s && *s != '"'; s++) if (*s == '\\' && s[1]) s++;
		return *s == '"' ? s + 1 : NULL;
	}
	if (*s == '{' || *s == '[') {
		char close = *s == '{' ? '}' : ']';
		s = ws(s + 1);
		if (*s == close) return s + 1;
		for (;;) {
			if (close == '}') {
				if (*s != '"' || !(s = skip_value_d(s, depth + 1))) return NULL;
				s = ws(s);
				if (*s++ != ':') return NULL;
			}
			if (!(s = skip_value_d(s, depth + 1))) return NULL;
			s = ws(s);
			if (*s == ',') { s = ws(s + 1); continue; }
			return *s == close ? s + 1 : NULL;
		}
	}
	if (!*s || *s == ',' || *s == '}' || *s == ']') return NULL;
	while (*s && *s != ',' && *s != '}' && *s != ']' && !isspace((unsigned char)*s)) s++;
	return s;
}
const char *json_skip_value(const char *s) { return skip_value_d(s, 0); }
#define skip_value json_skip_value

int json_parse_flat(const char *s, kv *out, int max)
{
	int n = 0;
	s = ws(s);
	if (*s++ != '{') return -1;
	s = ws(s);
	if (*s == '}') return 0;
	for (;;) {
		if (n >= max) return -1;
		s = ws(s);
		if (!(s = parse_str(s, out[n].key, sizeof out[n].key))) return -1;
		s = ws(s);
		if (*s++ != ':') return -1;
		s = ws(s);
		if (*s == '"') {
			if (!(s = parse_str(s, out[n].val, sizeof out[n].val))) return -1;
		} else if (*s == '{' || *s == '[') {
			/* nested value: not representable here, see json_raw_field */
			if (!(s = skip_value(s))) return -1;
			out[n].val[0] = 0;
		} else {
			size_t o = 0;
			while (*s && *s != ',' && *s != '}' && !isspace((unsigned char)*s))
				if (o + 1 < sizeof out[n].val) out[n].val[o++] = *s++; else s++;
			out[n].val[o] = 0;
			if (!o) return -1;
		}
		n++;
		s = ws(s);
		if (*s == ',') { s++; continue; }
		if (*s == '}') return n;
		return -1;
	}
}

const char *kv_get(const kv *a, int n, const char *key)
{
	for (int i = 0; i < n; i++) if (!strcmp(a[i].key, key)) return a[i].val;
	return NULL;
}

/* the raw text of a top-level member of a JSON object, malloc'd; NULL if absent or malformed */
char *json_raw_field(const char *s, const char *key)
{
	char k[64];
	s = ws(s);
	if (*s++ != '{') return NULL;
	for (;;) {
		s = ws(s);
		if (*s == '}' || !(s = parse_str(s, k, sizeof k))) return NULL;
		s = ws(s);
		if (*s++ != ':') return NULL;
		s = ws(s);
		const char *e = skip_value_d(s, 0);
		if (!e) return NULL;
		if (!strcmp(k, key)) {
			char *r = malloc(e - s + 1);
			if (!r) return NULL;
			memcpy(r, s, e - s);
			r[e - s] = 0;
			return r;
		}
		s = ws(e);
		if (*s++ != ',') return NULL;
	}
}
