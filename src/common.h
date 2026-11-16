#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>

typedef enum {
	RC_OK, RC_RST, RC_TIMEOUT, RC_ALERT, RC_FORGED, RC_DNS_SPOOFED, RC_UNREACHABLE, RC_ERROR, RC_STALLED, RC_COUNT
} result_class;

const char *class_name(result_class c);

typedef struct {
	const char *host;      /* SNI / Host header / DNS name */
	const char *ip;        /* literal address, skips resolving */
	int family;            /* 0 any, 4, 6 */
	int port;              /* 0 = protocol default */
	uint32_t mark;         /* SO_MARK, 0 = none */
	int timeout_ms;
	int repeat;
	int pace_ms;           /* pause between repeats */
	const char *template_path;
	const char *path;      /* http */
	const char *server;    /* dns */
	const char *ref;       /* dns reference resolver */
	int dns_wait_ms;
	int min_bytes;         /* fetch: stop when this many bytes came back on the connection */
	const char *ca;        /* fetch: CA bundle file, default /etc/ssl/certs/ca-certificates.crt */
} probe_opts;

typedef struct {
	result_class cls;
	int ms;                /* send -> verdict */
	int connect_ms;
	int status;            /* http status */
	int bytes;             /* fetch: bytes received on the TCP connection, handshake included */
	int hs_ms;             /* fetch: TLS handshake time */
	char detail[48];
	char info[256];        /* dns answers, space separated */
} presult;

/* net.c */
int64_t now_ms(void);
int priv_drop(const char *user, int keep_net_admin);
int net_resolve(const char *host, const char *ip, int family, int port, int socktype,
		struct sockaddr_storage *ss, socklen_t *sl);
int net_socket(int family, int type, uint32_t mark);
int net_connect(int fd, const struct sockaddr_storage *ss, socklen_t sl, int timeout_ms);
int net_wait(int fd, short events, int64_t deadline);   /* 0 ready, -1 errno (ETIMEDOUT) */
void net_conn_fail(presult *r, int e);
int net_write_all(int fd, const void *buf, size_t len, int64_t deadline);
/* >0 bytes, 0 eof, -1 error (errno; ETIMEDOUT on deadline) */
ssize_t net_read(int fd, void *buf, size_t len, int64_t deadline);
void set_detail(presult *r, const char *fmt, ...);

/* hello.c */
size_t hello_build_tcp(uint8_t *out, size_t cap, const char *sni);   /* full TLS record */
size_t hello_build_quic(uint8_t *out, size_t cap, const char *sni,
			const uint8_t *scid, size_t scid_len);          /* handshake msg, no record header */
size_t hello_from_template(const uint8_t *tpl, size_t tlen, const char *sni, uint8_t *out, size_t cap);
size_t hello_load(const probe_opts *o, uint8_t *out, size_t cap);
bool hello_get_sni(const uint8_t *rec, size_t len, char *sni, size_t sl);
void rand_bytes(void *p, size_t n);

/* classify.c */
/* returns false if more data is needed */
bool tls_classify(const uint8_t *buf, size_t n, presult *r);
bool http_classify(const uint8_t *buf, size_t n, const char *host, bool eof, presult *r);

/* quic.c */
typedef struct { uint8_t key[16], iv[12], hp[16]; } quic_keys;
int quic_initial_keys(const uint8_t *dcid, size_t dl, bool server, quic_keys *k);
size_t quic_seal_initial(uint8_t *out, size_t cap, const quic_keys *k,
			 const uint8_t *dcid, size_t dl, const uint8_t *scid, size_t sl,
			 const uint8_t *crypto, size_t clen, size_t min_total,
			 uint64_t coff, uint32_t pn);
bool quic_open_initial(const uint8_t *pkt, size_t len, const quic_keys *k,
		       uint8_t *plain, size_t *plen);
/* 1 if a CRYPTO frame found at offset 0 (first byte of it in *b), 0 otherwise */
size_t quic_initial_max_chunk(size_t dl, size_t sl);
int quic_crypto_first(const uint8_t *plain, size_t plen, uint8_t *b);
bool quic_classify(const uint8_t *dg, size_t n, const uint8_t *dcid, size_t dl, presult *r);

/* probes */
void probe_tls(const probe_opts *o, const struct sockaddr_storage *ss, socklen_t sl, presult *r);
void probe_quic(const probe_opts *o, const struct sockaddr_storage *ss, socklen_t sl, presult *r);
void probe_http(const probe_opts *o, const struct sockaddr_storage *ss, socklen_t sl, presult *r);
void probe_dns(const probe_opts *o, presult *r);
/* fetch.c: full TLS + HTTP download, needs mbedtls (WITH_MBEDTLS=1); otherwise reports error/no_mbedtls */
void probe_fetch(const probe_opts *o, const struct sockaddr_storage *ss, socklen_t sl, presult *r);

/* dns.c helpers (tested) */
size_t dns_build_query(uint8_t *out, size_t cap, uint16_t id, const char *name, uint16_t type);
/* parses answers into space separated text; returns number of answers, -1 on malformed */
int dns_parse_answers(const uint8_t *p, size_t n, uint16_t *id, char *out, size_t osz);
bool ip_is_bogon(const char *ip);
