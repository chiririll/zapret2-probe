#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef ZPROBE
#define ZPROBE "build/zprobe"      /* the binary under test, set by the Makefile for other BUILD dirs */
#endif
static int g_fail, g_total;
#define CHECK(cond) do { g_total++; if (!(cond)) { g_fail++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define DONE() do { printf("%s: %d/%d passed\n", __FILE__, g_total - g_fail, g_total); return g_fail ? 1 : 0; } while (0)
static inline int unhex(const char *h, unsigned char *out)
{
	int n = 0;
	for (; h[0] && h[1]; h += 2) { unsigned v; sscanf(h, "%2x", &v); out[n++] = v; }
	return n;
}
