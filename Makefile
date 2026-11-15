# zprobe - TLS/QUIC/HTTP/DNS reachability probes with JSON output
# Plain make; builds on desktop Linux and in the OpenWrt SDK.
CC      ?= cc
CFLAGS  ?= -O2
override CFLAGS  += -std=gnu99 -Wall -Wextra -Wno-unused-parameter -Wno-array-parameter
UPSTREAM ?= upstream/zapret2/nfq2
CRYPTO_SRC = $(addprefix $(UPSTREAM)/crypto/,aes.c gcm.c aes-gcm.c hkdf.c hmac.c usha.c sha224-256.c)
override CPPFLAGS += -I$(UPSTREAM)/crypto -Isrc
SRC     = src/main.c src/net.c src/json.c src/hello.c src/classify.c src/quic.c src/probe_tls.c src/dns.c src/priv.c
BUILD   ?= build
OBJ     = $(patsubst %.c,$(BUILD)/%.o,$(SRC) $(CRYPTO_SRC))
LIBOBJ  = $(filter-out $(BUILD)/src/main.o,$(OBJ))
PREFIX  ?= /usr
DESTDIR ?=
SHAREDIR ?= $(PREFIX)/share/zapret2/probe
override CPPFLAGS += -DTEMPLATE_DIR='"$(SHAREDIR)/templates"'

all: $(BUILD)/zprobe

$(BUILD)/%.o: %.c src/common.h src/json.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD)/zprobe: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/tests/%: tests/%.c $(LIBOBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

test: all $(BUILD)/tests/test_unit $(BUILD)/tests/test_local
	$(BUILD)/tests/test_unit
	$(BUILD)/tests/test_local

install: $(BUILD)/zprobe
	install -D -m 0755 $(BUILD)/zprobe $(DESTDIR)$(PREFIX)/bin/zprobe
	install -d $(DESTDIR)$(SHAREDIR)/templates
	install -m 0644 templates/*.bin $(DESTDIR)$(SHAREDIR)/templates/

clean:
	rm -rf $(BUILD)

.PHONY: all test install clean
