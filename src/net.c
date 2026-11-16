#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "common.h"

static const char *const names[RC_COUNT] = {
	"ok", "rst", "timeout", "alert", "forged", "dns_spoofed", "unreachable", "error", "stalled"
};
const char *class_name(result_class c) { return c < RC_COUNT ? names[c] : "error"; }

int64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void set_detail(presult *r, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(r->detail, sizeof r->detail, fmt, ap);
	va_end(ap);
}

int net_resolve(const char *host, const char *ip, int family, int port, int socktype,
		struct sockaddr_storage *ss, socklen_t *sl)
{
	struct addrinfo hints, *res;
	char ps[8];
	memset(&hints, 0, sizeof hints);
	hints.ai_family = family == 4 ? AF_INET : family == 6 ? AF_INET6 : AF_UNSPEC;
	hints.ai_socktype = socktype;
	if (ip) hints.ai_flags = AI_NUMERICHOST;
	snprintf(ps, sizeof ps, "%d", port);
	if (getaddrinfo(ip ? ip : host, ps, &hints, &res) || !res) return -1;
	memcpy(ss, res->ai_addr, res->ai_addrlen);
	*sl = res->ai_addrlen;
	freeaddrinfo(res);
	return 0;
}

int net_socket(int family, int type, uint32_t mark)
{
	int fd = socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) return -1;
	if (mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof mark) < 0) {
		int e = errno;
		close(fd);
		errno = e;
		return -1;
	}
	return fd;
}

static int wait_fd(int fd, short ev, int64_t deadline)
{
	for (;;) {
		int64_t left = deadline - now_ms();
		if (left < 0) left = 0;
		struct pollfd p = { .fd = fd, .events = ev };
		int n = poll(&p, 1, (int)left);
		if (n > 0) return 0;
		if (n == 0) { errno = ETIMEDOUT; return -1; }
		if (errno != EINTR) return -1;
	}
}

int net_wait(int fd, short events, int64_t deadline) { return wait_fd(fd, events, deadline); }

int net_connect(int fd, const struct sockaddr_storage *ss, socklen_t sl, int timeout_ms)
{
	if (connect(fd, (const struct sockaddr *)ss, sl) == 0) return 0;
	if (errno != EINPROGRESS) return errno;
	if (wait_fd(fd, POLLOUT, now_ms() + timeout_ms)) return errno;
	int err = 0;
	socklen_t l = sizeof err;
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l) < 0) return errno;
	return err;
}

int net_write_all(int fd, const void *buf, size_t len, int64_t deadline)
{
	const uint8_t *p = buf;
	while (len) {
		ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				if (wait_fd(fd, POLLOUT, deadline)) return -1;
				continue;
			}
			return -1;
		}
		p += n; len -= n;
	}
	return 0;
}

ssize_t net_read(int fd, void *buf, size_t len, int64_t deadline)
{
	for (;;) {
		ssize_t n = recv(fd, buf, len, 0);
		if (n >= 0) return n;
		if (errno == EINTR) continue;
		if (errno != EAGAIN) return -1;
		if (wait_fd(fd, POLLIN, deadline)) return -1;
	}
}
