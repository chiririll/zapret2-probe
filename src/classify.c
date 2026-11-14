#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "common.h"

bool tls_classify(const uint8_t *b, size_t n, presult *r)
{
	if (!n) return false;
	if (b[0] == 'H') {                       /* "HTTP/": injected block page or plaintext answer */
		size_t m = n < 5 ? n : 5;
		if (!memcmp(b, "HTTP/", m)) {
			if (n < 5) return false;
			r->cls = RC_FORGED; set_detail(r, "http_response");
			return true;
		}
	}
	if (b[0] != 0x15 && b[0] != 0x16) {
		r->cls = RC_FORGED; set_detail(r, "garbage_0x%02x", b[0]);
		return true;
	}
	if (n >= 2 && b[1] != 0x03) {
		r->cls = RC_FORGED; set_detail(r, "bad_version");
		return true;
	}
	if (n < 7) return false;
	if (b[0] == 0x15) {
		r->cls = RC_ALERT; set_detail(r, "alert_%u", b[6]);
		return true;
	}
	if (b[5] == 2) {
		r->cls = RC_OK; set_detail(r, "server_hello");
		return true;
	}
	r->cls = RC_FORGED; set_detail(r, "unexpected_hs_%u", b[5]);
	return true;
}

/* final domain labels, used to tell a legitimate www/redirect from a block page */
static void base_domain(const char *h, char *out, size_t osz)
{
	const char *last = NULL, *prev = NULL;
	for (const char *p = h; *p; p++)
		if (*p == '.') { prev = last; last = p; }
	const char *start = prev ? prev + 1 : h;
	snprintf(out, osz, "%s", start);
	for (char *q = out; *q; q++) *q = tolower((unsigned char)*q);
}

static bool location_foreign(const char *loc, const char *host)
{
	const char *p = strstr(loc, "://");
	if (!p) return false;                    /* relative redirect */
	p += 3;
	char h[256];
	size_t i = 0;
	while (*p && *p != '/' && *p != ':' && *p != '?' && i + 1 < sizeof h) h[i++] = tolower((unsigned char)*p++);
	h[i] = 0;
	char want[256], got[256];
	base_domain(host, want, sizeof want);
	base_domain(h, got, sizeof got);
	return strcmp(want, got) != 0;
}

bool http_classify(const uint8_t *b, size_t n, const char *host, bool eof, presult *r)
{
	if (!n) return false;
	size_t m = n < 5 ? n : 5;
	if (memcmp(b, "HTTP/", m)) {
		r->cls = RC_FORGED; set_detail(r, "not_http");
		return true;
	}
	if (n < 12) return eof ? (r->cls = RC_FORGED, set_detail(r, "truncated"), true) : false;
	char line[16];
	memcpy(line, b + 9, 3); line[3] = 0;
	int st = atoi(line);
	if (st < 100 || st > 599) {
		r->cls = RC_FORGED; set_detail(r, "bad_status");
		return true;
	}
	r->status = st;
	/* need full headers for Location */
	const char *hdr = (const char *)b;
	const char *end = memmem(hdr, n, "\r\n\r\n", 4);
	if (!end && !eof && n < 8192) return false;
	size_t hl = end ? (size_t)(end - hdr) : n;
	r->cls = RC_OK;
	set_detail(r, "http_%d", st);
	if (st == 451) { r->cls = RC_FORGED; set_detail(r, "http_451"); return true; }
	if (st >= 300 && st < 400) {
		for (size_t i = 0; i < hl; i++) {
			if ((i == 0 || hdr[i - 1] == '\n') && hl - i > 9 && !strncasecmp(hdr + i, "location:", 9)) {
				char loc[512];
				size_t k = 0, j = i + 9;
				while (j < hl && hdr[j] == ' ') j++;
				while (j < hl && hdr[j] != '\r' && hdr[j] != '\n' && k + 1 < sizeof loc) loc[k++] = hdr[j++];
				loc[k] = 0;
				if (location_foreign(loc, host)) {
					r->cls = RC_FORGED; set_detail(r, "redirect_foreign");
				}
				break;
			}
		}
	}
	return true;
}
