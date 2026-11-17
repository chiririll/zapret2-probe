#pragma once
/* Lua check scripts: `zprobe check`, batch `cmd:"check"`, `zprobe check-info`. See lua.c. */
#include "common.h"
#include "json.h"

#ifndef CHECK_DIRS
#define CHECK_DIRS "/etc/zapret2/autotune/checks:/usr/share/zapret2/autotune/checks:/usr/share/zapret2/probe/checks"
#endif

/* search path, first match wins; empty list means CHECK_DIRS */
void check_add_dir(const char *dir);

/* Runs one job: `repeat` calls of the script's check (or one call of its prepare when phase is "prepare").
 * args_json is the raw JSON object for the script's arguments, NULL for none. Appends one JSON object to out.
 * Returns the number of results that were not ok. Without Lua support every result is error/no_lua. */
int run_check(const char *id, const probe_opts *o, const char *check, const char *phase,
	      const char *args_json, sbuf *out);

/* JSON array describing every script on the search path: name, title, protos, args */
void check_info(sbuf *out);

/* true when this build can run scripts */
bool check_have_lua(void);
