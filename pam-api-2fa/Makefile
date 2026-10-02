CC ?= cc
PKG_CONFIG ?= pkg-config
PREFIX ?= /usr
PAM_LIBDIR ?= $(shell $(PKG_CONFIG) --variable=libdir pam 2>/dev/null)/security
CFLAGS ?= -O2
WARNINGS = -Wall -Wextra -Wformat=2 -Werror -fPIC
DEPS_CFLAGS = $(shell $(PKG_CONFIG) --cflags libcurl json-c)
DEPS_LIBS = $(shell $(PKG_CONFIG) --libs libcurl json-c)

.PHONY: all install clean

all: pam_api_2fa.so

pam_api_2fa.so: src/pam_api_2fa.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 $(DEPS_CFLAGS) \
		-shared -Wl,-z,relro,-z,now -o $@ $< $(LDFLAGS) $(DEPS_LIBS)

install: pam_api_2fa.so
	install -D -o root -g root -m 0644 pam_api_2fa.so "$(DESTDIR)$(PAM_LIBDIR)/pam_api_2fa.so"
	install -D -o root -g root -m 0755 userdb/apiuser-userdb "$(DESTDIR)$(PREFIX)/sbin/apiuser-userdb"
	install -D -o root -g root -m 0644 systemd/io.local.apiuser.socket "$(DESTDIR)/etc/systemd/system/io.local.apiuser.socket"
	install -D -o root -g root -m 0644 systemd/io.local.apiuser@.service "$(DESTDIR)/etc/systemd/system/io.local.apiuser@.service"
	install -d -o root -g root -m 0700 "$(DESTDIR)/var/lib/apiusers"

clean:
	rm -f pam_api_2fa.so