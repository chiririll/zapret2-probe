#pragma once
#include <stddef.h>

typedef struct { char *p; size_t len, cap; } sbuf;
void sb_init(sbuf *b);
void sb_free(sbuf *b);
void sb_puts(sbuf *b, const char *s);
void sb_printf(sbuf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void sb_jstr(sbuf *b, const char *s);

typedef struct { char key[32]; char val[512]; } kv;
/* flat object only: {"k":"v","n":5,"b":true}; returns count or -1 */
int json_parse_flat(const char *s, kv *out, int max);
const char *kv_get(const kv *a, int n, const char *key);
