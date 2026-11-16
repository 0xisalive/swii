# ukvm - minimal low-latency UDP software KVM
#
# The host builds on macOS (Darwin); the client builds on FreeBSD. This
# Makefile detects the running OS and builds the binary native to it, while
# still exposing explicit `host` and `client` targets.

UNAME_S := $(shell uname -s)

CC      ?= cc
CSTD    := -std=c11
WARN    := -Wall -Wextra
OPT     := -O2
CFLAGS  ?= $(CSTD) $(WARN) $(OPT)

PREFIX  ?= /usr/local
BINDIR  := $(PREFIX)/bin

HOST_BIN   := ukvm-host
CLIENT_BIN := ukvm-client

HOST_SRC   := macos-host/main.c
CLIENT_SRC := freebsd-client/main.c

COMMON_HDR := common/protocol.h common/crypto.h common/hid_keymap.h

MACOS_FRAMEWORKS := -framework ApplicationServices -framework CoreFoundation

# Default target picks the binary appropriate to this machine.
ifeq ($(UNAME_S),Darwin)
all: host
else ifeq ($(UNAME_S),FreeBSD)
all: client
else
all:
	@echo "ukvm: unrecognised OS '$(UNAME_S)'."
	@echo "Build an explicit target: 'make host' (macOS) or 'make client' (FreeBSD)."
endif

.PHONY: all host client install install-host install-client clean

# macOS host. Linking the frameworks only makes sense on Darwin; on other
# systems we still compile for a syntax check without the frameworks.
host: $(HOST_SRC) $(COMMON_HDR)
ifeq ($(UNAME_S),Darwin)
	$(CC) $(CFLAGS) $(HOST_SRC) $(MACOS_FRAMEWORKS) -o $(HOST_BIN)
else
	$(CC) $(CFLAGS) $(HOST_SRC) -o $(HOST_BIN)
endif

# FreeBSD client.
client: $(CLIENT_SRC) $(COMMON_HDR)
	$(CC) $(CFLAGS) $(CLIENT_SRC) -o $(CLIENT_BIN)

# Install the binary native to this OS.
ifeq ($(UNAME_S),Darwin)
install: install-host
else ifeq ($(UNAME_S),FreeBSD)
install: install-client
else
install:
	@echo "ukvm: nothing to install on '$(UNAME_S)'."
endif

install-host: host
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(HOST_BIN) $(DESTDIR)$(BINDIR)/$(HOST_BIN)

install-client: client
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(CLIENT_BIN) $(DESTDIR)$(BINDIR)/$(CLIENT_BIN)

clean:
	rm -f $(HOST_BIN) $(CLIENT_BIN)
