#include "check.h"
#include "../src/common.h"
#include "../src/json.h"
#include <arpa/inet.h>

static void test_quic_vectors(void)
{
	/* RFC 9001 appendix A.1 */
	uint8_t dcid[8], ek[16], eiv[12], ehp[16];
	unhex("8394c8f03e515708", dcid);
	quic_keys k;
	CHECK(quic_initial_keys(dcid, 8, false, &k) == 0);
	unhex("1f369613dd76d5467730efcbe3b1a22d", ek); unhex("fa044b2f42a3fd3b46fb255c", eiv);
	unhex("9f50449e04a0e810283a1e9933adedd2", ehp);
	CHECK(!memcmp(k.key, ek, 16) && !memcmp(k.iv, eiv, 12) && !memcmp(k.hp, ehp, 16));
	CHECK(quic_initial_keys(dcid, 8, true, &k) == 0);
	unhex("cf3a5331653c364c88f0f379b6067e37", ek); unhex("0ac1493ca1905853b0bba03e", eiv);
	unhex("c206b8d9b9f0f37644430b490eeaa314", ehp);
	CHECK(!memcmp(k.key, ek, 16) && !memcmp(k.iv, eiv, 12) && !memcmp(k.hp, ehp, 16));
}

static void test_quic_roundtrip(void)
{
	uint8_t dcid[8], scid[8], msg[2048], pkt[1500], plain[2048];
	rand_bytes(dcid, 8); rand_bytes(scid, 8);
	size_t ml = hello_build_quic(msg, sizeof msg, "example.com", scid, 8);
	CHECK(ml > 100 && msg[0] == 1);
	quic_keys k;
	size_t chunk = quic_initial_max_chunk(8, 8), c1 = ml < chunk ? ml : chunk;
	CHECK(ml > chunk);                                /* ML-KEM hello needs two packets */
	CHECK(quic_initial_keys(dcid, 8, false, &k) == 0);
	size_t pl = quic_seal_initial(pkt, sizeof pkt, &k, dcid, 8, scid, 8, msg, c1, 1200, 0, 0);
	CHECK(pl == 1200);
	size_t plen = sizeof plain;
	CHECK(quic_open_initial(pkt, pl, &k, plain, &plen));
	CHECK(plain[0] == 6 && plen >= c1 + 5 && !memcmp(plain + 5, msg, c1));
	{
		uint8_t p2[1500], pl2b[2048];
		size_t n2 = quic_seal_initial(p2, sizeof p2, &k, dcid, 8, scid, 8, msg + c1, ml - c1, 1200, c1, 1);
		size_t l2 = sizeof pl2b;
		CHECK(n2 == 1200 && quic_open_initial(p2, n2, &k, pl2b, &l2) && !memcmp(pl2b + 5, msg + c1, ml - c1));
	}
	uint8_t b = 0;
	CHECK(quic_crypto_first(plain, plen, &b) == 1 && b == 1);
	pkt[700] ^= 1;                                   /* corrupted ciphertext must not open */
	plen = sizeof plain;
	CHECK(!quic_open_initial(pkt, pl, &k, plain, &plen));
	/* server side classification */
	uint8_t sh[8] = { 2, 0, 0, 4, 3, 3, 0, 0 }, sp[200];
	quic_keys sk;
	quic_initial_keys(dcid, 8, true, &sk);
	size_t sl = quic_seal_initial(sp, sizeof sp, &sk, scid, 8, dcid, 8, sh, sizeof sh, 100, 0, 0);
	presult r = { 0 };
	CHECK(sl && quic_classify(sp, sl, dcid, 8, &r) && r.cls == RC_OK && !strcmp(r.detail, "server_hello"));
	sp[sl - 3] ^= 1;
	memset(&r, 0, sizeof r);
	CHECK(quic_classify(sp, sl, dcid, 8, &r) && r.cls == RC_FORGED);
}

static void test_tls_classify(void)
{
	presult r;
	uint8_t sh[] = { 0x16, 3, 3, 0, 4, 2, 0, 0, 0 };
	uint8_t al[] = { 0x15, 3, 3, 0, 2, 2, 40 };
	const char *http = "HTTP/1.1 403 Forbidden\r\n\r\n";
	memset(&r, 0, sizeof r);
	CHECK(!tls_classify(sh, 3, &r));
	CHECK(tls_classify(sh, sizeof sh, &r) && r.cls == RC_OK);
	memset(&r, 0, sizeof r);
	CHECK(tls_classify(al, sizeof al, &r) && r.cls == RC_ALERT && !strcmp(r.detail, "alert_40"));
	memset(&r, 0, sizeof r);
	CHECK(tls_classify((const uint8_t *)http, strlen(http), &r) && r.cls == RC_FORGED);
	memset(&r, 0, sizeof r);
	CHECK(!tls_classify((const uint8_t *)"HT", 2, &r));
	uint8_t junk[] = { 0x00, 0x01, 0x02 };
	CHECK(tls_classify(junk, 3, &r) && r.cls == RC_FORGED);
}

static void test_http_classify(void)
{
	presult r;
	const char *ok = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
	const char *www = "HTTP/1.1 301 Moved\r\nLocation: https://www.example.com/\r\n\r\n";
	const char *evil = "HTTP/1.1 302 Found\r\nLocation: http://block.isp.example/stop\r\n\r\n";
	const char *rel = "HTTP/1.1 302 Found\r\nlocation: /login\r\n\r\n";
	const char *legal = "HTTP/1.1 451 Unavailable\r\n\r\n";
	memset(&r, 0, sizeof r);
	CHECK(http_classify((const uint8_t *)ok, strlen(ok), "example.com", false, &r) && r.cls == RC_OK && r.status == 200);
	memset(&r, 0, sizeof r);
	CHECK(http_classify((const uint8_t *)www, strlen(www), "example.com", false, &r) && r.cls == RC_OK);
	memset(&r, 0, sizeof r);
	CHECK(http_classify((const uint8_t *)evil, strlen(evil), "example.com", false, &r) && r.cls == RC_FORGED);
	memset(&r, 0, sizeof r);
	CHECK(http_classify((const uint8_t *)rel, strlen(rel), "example.com", false, &r) && r.cls == RC_OK);
	memset(&r, 0, sizeof r);
	CHECK(http_classify((const uint8_t *)legal, strlen(legal), "example.com", false, &r) && r.cls == RC_FORGED);
	memset(&r, 0, sizeof r);
	CHECK(!http_classify((const uint8_t *)"HTTP/1.1 20", 11, "example.com", false, &r));
}

static void test_hello(void)
{
	uint8_t a[4096], b[4096];
	char sni[256];
	size_t n = hello_build_tcp(a, sizeof a, "short.example");
	CHECK(n > 1400 && n < 2000);                      /* spans two segments, like a browser with ML-KEM */
	CHECK(a[0] == 0x16 && 5 + (a[3] << 8 | a[4]) == n);
	CHECK(((a[6] << 16) | (a[7] << 8) | a[8]) == n - 9);
	CHECK(hello_get_sni(a, n, sni, sizeof sni) && !strcmp(sni, "short.example"));
	const char *longer = "a-much-longer-host-name.sub.example.org";
	size_t m = hello_from_template(a, n, longer, b, sizeof b);
	CHECK(m == n + strlen(longer) - strlen("short.example"));
	CHECK(5 + (b[3] << 8 | b[4]) == m && ((b[6] << 16) | (b[7] << 8) | b[8]) == m - 9);
	CHECK(hello_get_sni(b, m, sni, sizeof sni) && !strcmp(sni, longer));
	size_t k = hello_from_template(b, m, "x.io", a, sizeof a);
	CHECK(k && hello_get_sni(a, k, sni, sizeof sni) && !strcmp(sni, "x.io"));
	CHECK(5 + (a[3] << 8 | a[4]) == k);
	/* two builds differ (random, session id, key shares) */
	uint8_t c1[4096], c2[4096];
	size_t l1 = hello_build_tcp(c1, sizeof c1, "x.io"), l2 = hello_build_tcp(c2, sizeof c2, "x.io");
	CHECK(l1 == l2 && memcmp(c1, c2, l1));
}

static void test_json(void)
{
	kv a[8];
	int n = json_parse_flat(" {\"id\":\"a\\\"b\",\"n\": 5, \"t\":true,\"h\":\"x.org\"} ", a, 8);
	CHECK(n == 4);
	CHECK(!strcmp(kv_get(a, n, "id"), "a\"b") && !strcmp(kv_get(a, n, "n"), "5") && !strcmp(kv_get(a, n, "t"), "true"));
	CHECK(kv_get(a, n, "zzz") == NULL);
	CHECK(json_parse_flat("{\"a\":}", a, 8) < 0);
	CHECK(json_parse_flat("nope", a, 8) < 0);
	CHECK(json_parse_flat("{}", a, 8) == 0);
	sbuf b;
	sb_init(&b);
	sb_jstr(&b, "q\"\\\n\x01");
	CHECK(!strcmp(b.p, "\"q\\\"\\\\\\n\\u0001\""));
	sb_free(&b);
}

static void test_dns(void)
{
	uint8_t q[100];
	size_t ql = dns_build_query(q, sizeof q, 0x1234, "ex.com", 1);
	CHECK(ql == 12 + 1 + 2 + 1 + 3 + 1 + 4 && q[12] == 2 && !memcmp(q + 13, "ex", 2));
	/* craft a reply: question echoed + A 93.184.216.34 via compression pointer */
	uint8_t r[100];
	memcpy(r, q, ql);
	r[2] = 0x81; r[3] = 0x80; r[7] = 1;
	size_t p = ql;
	r[p++] = 0xc0; r[p++] = 12; r[p++] = 0; r[p++] = 1; r[p++] = 0; r[p++] = 1;
	r[p++] = 0; r[p++] = 0; r[p++] = 0; r[p++] = 60; r[p++] = 0; r[p++] = 4;
	r[p++] = 93; r[p++] = 184; r[p++] = 216; r[p++] = 34;
	char out[64];
	uint16_t id;
	CHECK(dns_parse_answers(r, p, &id, out, sizeof out) == 1 && id == 0x1234 && !strcmp(out, "93.184.216.34"));
	CHECK(dns_parse_answers(r, p - 2, &id, out, sizeof out) < 0);
	r[3] = 0x83;
	CHECK(dns_parse_answers(r, p, &id, out, sizeof out) == -5);   /* NXDOMAIN */
	CHECK(ip_is_bogon("127.0.0.1") && ip_is_bogon("10.1.2.3") && ip_is_bogon("192.168.0.1") &&
	      ip_is_bogon("0.0.0.0") && ip_is_bogon("::1") && ip_is_bogon("fd00::1"));
	CHECK(!ip_is_bogon("93.184.216.34") && !ip_is_bogon("2606:4700::1111") && !ip_is_bogon("172.32.0.1"));
	CHECK(ip_is_bogon("172.16.5.5"));
}

int main(void)
{
	test_quic_vectors();
	test_quic_roundtrip();
	test_tls_classify();
	test_http_classify();
	test_hello();
	test_json();
	test_dns();
	DONE();
}
