#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include "common.h"

/* Drop to an unprivileged user. Only CAP_NET_ADMIN (needed for SO_MARK) survives, and only if keep_net_admin.
 * Raw capset(2), no libcap. Same idea as nfq2/sec.c. */
int priv_drop(const char *user, int keep_net_admin)
{
	struct passwd *pw;
	struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct d[2];
	uint32_t bit = keep_net_admin ? (1u << CAP_NET_ADMIN) : 0;

	if (getuid() != 0) {
		/* nothing to drop; refuse to pretend */
		fprintf(stderr, "zprobe: --user needs root\n");
		return -1;
	}
	if (!(pw = getpwnam(user))) { fprintf(stderr, "zprobe: unknown user '%s'\n", user); return -1; }
	if (!pw->pw_uid) { fprintf(stderr, "zprobe: --user must not be root\n"); return -1; }
	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0)) { perror("zprobe: PR_SET_KEEPCAPS"); return -1; }
	if (setgroups(0, NULL) || setgid(pw->pw_gid) || setuid(pw->pw_uid)) { perror("zprobe: setuid"); return -1; }
	memset(d, 0, sizeof d);
	d[0].effective = d[0].permitted = bit;
	if (syscall(SYS_capset, &h, d)) { perror("zprobe: capset"); return -1; }
	/* make sure root cannot come back */
	if (setuid(0) == 0) { fputs("zprobe: dropped privileges can be regained\n", stderr); return -1; }
	return 0;
}
