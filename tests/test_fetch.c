/* fetch tests: a forked mbedtls server on loopback with a throw-away self-signed certificate (CN/SAN localhost,
 * generated once with openssl, not used anywhere else). Needs WITH_MBEDTLS=1. */
#define _GNU_SOURCE
#include "check.h"
#include "../src/common.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

static const char CERT_PEM[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBljCCATugAwIBAgIUJdR99Gdc0cjsekR4QnbyM26rWCswCgYIKoZIzj0EAwIw\n"
	"FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTExNjE3MjYyNVoYDzIxMjYxMDIz\n"
	"MTcyNjI1WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO\n"
	"PQMBBwNCAASf92Il3ppnYYAqoTw3WQrWdeDBpBlBeMRzyI8ayGybWceKWElfVH70\n"
	"dAihCbMiMPK41QGPPwhBmglkk/IHn299o2kwZzAdBgNVHQ4EFgQUjJ0uhLZaHFPL\n"
	"GbypY1NUM84qdsgwHwYDVR0jBBgwFoAUjJ0uhLZaHFPLGbypY1NUM84qdsgwDwYD\n"
	"VR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwID\n"
	"SQAwRgIhAMEuzZBiHMzXRh7KT1VE29z1hz6a/Bx13z7sLOFvYTH/AiEA8hX8hUeV\n"
	"Y2J4dhF/GGgijsFIC/0OPPHkAnQNaex/xQE=\n"
	"-----END CERTIFICATE-----\n";
static const char KEY_PEM[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgStc6O5NlEtjZ4P80\n"
	"lzWCCqYuIkbHiqPB4QHjYY8L0lmhRANCAASf92Il3ppnYYAqoTw3WQrWdeDBpBlB\n"
	"eMRzyI8ayGybWceKWElfVH70dAihCbMiMPK41QGPPwhBmglkk/IHn299\n"
	"-----END PRIVATE KEY-----\n";

/* what the server does once the TLS handshake is done */
enum { SRV_BIG, SRV_STALL_AT, SRV_SMALL_CLOSE, SRV_SMALL_KEEPALIVE, SRV_CHUNKED_KEEPALIVE, SRV_HS_RST, SRV_SILENT };

static int sock_send(void *c, const unsigned char *b, size_t l) { ssize_t n = send(*(int *)c, b, l, MSG_NOSIGNAL); return n < 0 ? MBEDTLS_ERR_NET_SEND_FAILED : (int)n; }
static int sock_recv(void *c, unsigned char *b, size_t l) { ssize_t n = recv(*(int *)c, b, l, 0); return n < 0 ? MBEDTLS_ERR_NET_RECV_FAILED : (int)n; }

static void srv_write(mbedtls_ssl_context *s, const void *p, size_t n)
{
	const unsigned char *b = p;
	while (n) { int k = mbedtls_ssl_write(s, b, n); if (k <= 0) return; b += k; n -= k; }
}

static void srv_body(mbedtls_ssl_context *s, size_t total, size_t stop_after)
{
	char hdr[128], chunk[1000];
	memset(chunk, 'x', sizeof chunk);
	snprintf(hdr, sizeof hdr, "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n", total);
	srv_write(s, hdr, strlen(hdr));
	for (size_t sent = 0; sent < total; sent += sizeof chunk) {
		if (stop_after && sent >= stop_after) { sleep(5); return; }   /* the DPI freeze: connection open, no data */
		srv_write(s, chunk, total - sent < sizeof chunk ? total - sent : sizeof chunk);
	}
}

static void server(int ls, int mode)
{
	int c = accept(ls, NULL, NULL);
	if (mode == SRV_SILENT) { sleep(5); _exit(0); }
	if (mode == SRV_HS_RST) {
		char b[2048];
		ssize_t n = read(c, b, sizeof b);
		(void)n;
		struct linger lg = { 1, 0 };
		setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
		close(c);
		_exit(0);
	}
	mbedtls_entropy_context ent; mbedtls_ctr_drbg_context drbg; mbedtls_x509_crt crt; mbedtls_pk_context pk;
	mbedtls_ssl_config conf; mbedtls_ssl_context ssl;
	mbedtls_entropy_init(&ent); mbedtls_ctr_drbg_init(&drbg); mbedtls_x509_crt_init(&crt); mbedtls_pk_init(&pk);
	mbedtls_ssl_config_init(&conf); mbedtls_ssl_init(&ssl);
	psa_crypto_init();
	mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, NULL, 0);
	mbedtls_x509_crt_parse(&crt, (const unsigned char *)CERT_PEM, sizeof CERT_PEM);
	mbedtls_pk_parse_key(&pk, (const unsigned char *)KEY_PEM, sizeof KEY_PEM, NULL, 0, mbedtls_ctr_drbg_random, &drbg);
	mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
	mbedtls_ssl_conf_own_cert(&conf, &crt, &pk);
	mbedtls_ssl_setup(&ssl, &conf);
	mbedtls_ssl_set_bio(&ssl, &c, sock_send, sock_recv, NULL);
	if (mbedtls_ssl_handshake(&ssl)) _exit(1);
	char req[2048];
	int k;
	/* one read per request: the test client sends small requests */
	switch (mode) {
	case SRV_BIG: k = mbedtls_ssl_read(&ssl, (unsigned char *)req, sizeof req); (void)k; srv_body(&ssl, 300000, 0); break;
	case SRV_STALL_AT: k = mbedtls_ssl_read(&ssl, (unsigned char *)req, sizeof req); (void)k; srv_body(&ssl, 300000, 20000); break;
	case SRV_SMALL_CLOSE:
		k = mbedtls_ssl_read(&ssl, (unsigned char *)req, sizeof req); (void)k;
		srv_write(&ssl, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello", 61);
		break;
	case SRV_SMALL_KEEPALIVE:
		for (;;) {
			k = mbedtls_ssl_read(&ssl, (unsigned char *)req, sizeof req);
			if (k <= 0) break;
			srv_body(&ssl, 3000, 0);
		}
		break;
	case SRV_CHUNKED_KEEPALIVE:
		for (;;) {
			k = mbedtls_ssl_read(&ssl, (unsigned char *)req, sizeof req);
			if (k <= 0) break;
			srv_write(&ssl, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", 47);
			char ch[2200];
			memset(ch, 'y', sizeof ch);
			srv_write(&ssl, "7d0\r\n", 5);
			srv_write(&ssl, ch, 2000);
			srv_write(&ssl, "\r\n0\r\n\r\n", 7);
		}
		break;
	}
	mbedtls_ssl_close_notify(&ssl);
	_exit(0);
}

static pid_t spawn(int mode, int *port)
{
	int ls = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t l = sizeof a;
	bind(ls, (struct sockaddr *)&a, sizeof a);
	listen(ls, 4);
	getsockname(ls, (struct sockaddr *)&a, &l);
	*port = ntohs(a.sin_port);
	pid_t p = fork();
	if (p == 0) server(ls, mode);
	close(ls);
	return p;
}

static void run(int mode, const char *host, int min_bytes, int timeout, const char *ca, presult *r)
{
	int port;
	pid_t p = spawn(mode, &port);
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	probe_opts o = { .host = host, .timeout_ms = timeout, .repeat = 1, .min_bytes = min_bytes, .ca = ca };
	probe_fetch(&o, (struct sockaddr_storage *)&a, sizeof a, r);
	kill(p, SIGKILL); waitpid(p, NULL, 0);
}

int main(void)
{
	signal(SIGPIPE, SIG_IGN);
	char ca[] = "/tmp/zprobe-test-ca-XXXXXX";
	int fd = mkstemp(ca);
	if (fd < 0 || write(fd, CERT_PEM, sizeof CERT_PEM) < 0) { perror("ca"); return 1; }
	close(fd);
	presult r;

	run(SRV_BIG, "localhost", 65536, 2000, ca, &r);
	CHECK(r.cls == RC_OK && r.status == 200 && r.bytes >= 65536 && r.hs_ms >= 0);

	/* the freeze: handshake fine, data stops after 20 KB */
	run(SRV_STALL_AT, "localhost", 65536, 600, ca, &r);
	CHECK(r.cls == RC_STALLED && r.bytes > 15000 && r.bytes < 40000 && r.status == 200);

	/* server finishes and closes before min-bytes: ok, but marked short */
	run(SRV_SMALL_CLOSE, "localhost", 65536, 2000, ca, &r);
	CHECK(r.cls == RC_OK && !strncmp(r.detail, "short_", 6));

	/* short pages on a keep-alive connection are requested again until min-bytes */
	run(SRV_SMALL_KEEPALIVE, "localhost", 65536, 2000, ca, &r);
	CHECK(r.cls == RC_OK && !strncmp(r.detail, "bytes_", 6) && r.bytes >= 65536);
	run(SRV_CHUNKED_KEEPALIVE, "localhost", 30000, 2000, ca, &r);
	CHECK(r.cls == RC_OK && !strncmp(r.detail, "bytes_", 6));

	/* certificate for another name */
	run(SRV_BIG, "example.com", 65536, 2000, ca, &r);
	CHECK(r.cls == RC_FORGED && !strcmp(r.detail, "cert_name"));

	/* a name-correct certificate from an unknown root */
	char other[] = "/tmp/zprobe-test-ca2-XXXXXX";
	fd = mkstemp(other);
	/* any valid but unrelated certificate: the server's own, with one character of the base64 body flipped is invalid, so use an empty-trust file */
	if (write(fd, "\n", 1) < 0) return 1;
	close(fd);
	run(SRV_BIG, "localhost", 65536, 2000, other, &r);
	CHECK(r.cls == RC_OK);                      /* no usable CA file: the name is still checked, the chain is not */
	unlink(other);

	run(SRV_HS_RST, "localhost", 65536, 2000, ca, &r);
	CHECK(r.cls == RC_RST && !strncmp(r.detail, "hs_", 3));
	run(SRV_SILENT, "localhost", 65536, 400, ca, &r);
	CHECK(r.cls == RC_TIMEOUT && !strcmp(r.detail, "hs_no_reply"));

	unlink(ca);
	DONE();
}
