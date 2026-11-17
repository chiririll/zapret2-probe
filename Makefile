# zprobe - TLS/QUIC/HTTP/DNS reachability probes with JSON output
# Plain make; builds on desktop Linux and in the OpenWrt SDK.
CC      ?= cc
CFLAGS  ?= -O2
override CFLAGS  += -std=gnu99 -Wall -Wextra -Wno-unused-parameter -Wno-array-parameter
UPSTREAM ?= upstream/zapret2/nfq2
CRYPTO_SRC = $(addprefix $(UPSTREAM)/crypto/,aes.c gcm.c aes-gcm.c hkdf.c hmac.c usha.c sha224-256.c)
override CPPFLAGS += -I$(UPSTREAM)/crypto -Isrc
# fetch needs mbedtls: make WITH_MBEDTLS=1 [MBEDTLS_PREFIX=/path]. Without it everything else still builds with no dependencies.
WITH_MBEDTLS ?= 0
MBEDTLS_LIBDIR ?= $(MBEDTLS_PREFIX)/lib
# Lua check scripts: make WITH_LUA=1 [LUA_CFLAGS=-I... LUA_LIB=-l...]; by default pkg-config LUA_PKG (luajit, or lua5.3).
# Without it the `check` command answers error/no_lua and everything else works.
WITH_LUA ?= 0
LUA_PKG ?= luajit
SRC     = src/lua.c src/fetch.c src/main.c src/net.c src/json.c src/hello.c src/classify.c src/quic.c src/probe_tls.c src/dns.c src/priv.c
BUILD   ?= build
OBJ     = $(patsubst %.c,$(BUILD)/%.o,$(SRC) $(CRYPTO_SRC))
LIBOBJ  = $(filter-out $(BUILD)/src/main.o,$(OBJ))
PREFIX  ?= /usr
DESTDIR ?=
SHAREDIR ?= $(PREFIX)/share/zapret2/probe
ifeq ($(WITH_MBEDTLS),1)
override CPPFLAGS += -DWITH_MBEDTLS $(if $(MBEDTLS_PREFIX),-I$(MBEDTLS_PREFIX)/include)
override LDLIBS += $(if $(MBEDTLS_PREFIX),-L$(MBEDTLS_LIBDIR) )-lmbedtls -lmbedx509 -lmbedcrypto
TESTS_FETCH = $(BUILD)/tests/test_fetch
endif
GEN     = $(BUILD)/gen
override CPPFLAGS += -I$(GEN) -DZPROBE='"$(BUILD)/zprobe"'
ifeq ($(WITH_LUA),1)
LUA_CFLAGS ?= $(shell pkg-config --cflags $(LUA_PKG) 2>/dev/null)
LUA_LIB    ?= $(shell pkg-config --libs $(LUA_PKG) 2>/dev/null)
override CPPFLAGS += -DWITH_LUA $(LUA_CFLAGS)
override LDLIBS += $(LUA_LIB) -lm
TESTS_CHECK = $(BUILD)/tests/test_check
# the script tests run on the interpreter the router has: LUA_BIN=lua5.3 make test WITH_LUA=1 ...
LUA_BIN ?= $(shell for b in luajit lua5.3 lua; do command -v $$b && break; done 2>/dev/null)
endif
override CPPFLAGS += -DTEMPLATE_DIR='"$(SHAREDIR)/templates"'

all: $(BUILD)/zprobe

$(BUILD)/%.o: %.c src/common.h src/json.h src/check.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

# the argument normalizer is Lua text, compiled into the binary as a string
$(GEN)/runner_lua.h: src/runner.lua
	@mkdir -p $(GEN)
	{ echo 'static const char RUNNER_LUA[] ='; sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/"/' -e 's/$$/\\n"/' $<; echo ';'; } > $@
$(BUILD)/src/lua.o: $(GEN)/runner_lua.h

$(BUILD)/zprobe: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/%: tests/%.c $(LIBOBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

test: all $(BUILD)/tests/test_unit $(BUILD)/tests/test_local $(TESTS_FETCH) $(TESTS_CHECK)
	$(BUILD)/tests/test_unit
	$(BUILD)/tests/test_local
	$(if $(TESTS_FETCH),$(TESTS_FETCH))
	$(if $(TESTS_CHECK),$(TESTS_CHECK))
	$(if $(and $(TESTS_CHECK),$(LUA_BIN)),$(LUA_BIN) tests/scripts/run.lua)

install: $(BUILD)/zprobe
	install -D -m 0755 $(BUILD)/zprobe $(DESTDIR)$(PREFIX)/bin/zprobe
	install -d $(DESTDIR)$(SHAREDIR)/templates
	install -m 0644 templates/*.bin $(DESTDIR)$(SHAREDIR)/templates/
	install -d $(DESTDIR)$(SHAREDIR)/checks/lib
	install -m 0644 checks/*.lua $(DESTDIR)$(SHAREDIR)/checks/
	install -m 0644 checks/lib/*.lua $(DESTDIR)$(SHAREDIR)/checks/lib/

clean:
	rm -rf $(BUILD)

.PHONY: all test install clean
