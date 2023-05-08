TOPDIR := $(shell pwd)

VERSION := 0.1

# install directories
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=

ifeq ($(shell test -d .git && echo 1),1)
GIT_HASH := $(shell git describe --abbrev=8 --dirty --always --tags --long)
endif

EXTRA_CFLAGS = -std=gnu99 -Wall -Werror -DVERSION=\"$(VERSION)-g$(GIT_HASH)\"

.PHONY: all install
all: tiny-eep-encode tiny-eep-decode

clean:
	rm -f *.o tiny-eep-encode tiny-eep-decode

%.o: %.c
	$(CC) -c $< $(CLFAGS) $(EXTRA_CFLAGS)

tiny-eep-encode: tiny-eep-encode.o tiny-eep.h
tiny-eep-decode: tiny-eep-decode.o tiny-eep.h
	$(CC) $(LDFLAGS) -o $@ $^

install: tiny-eep-encode tiny-eep-decode
	install -D -m 0755 tiny-eep-encode $(DESTDIR)$(BINDIR)/tiny-eep-encode
	install -D -m 0755 tiny-eep-decode $(DESTDIR)$(BINDIR)/tiny-eep-decode
