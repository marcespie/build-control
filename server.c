/*
 * Copyright (c) 2025 Marc Espie <espie@openbsd.org>
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <stdio.h>
#include <err.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <poll.h>

#define HASHLENGTH 24

#define ARRAYINITSIZE 64
#define HASHINITSIZE 64


struct builder {
	char hash[HASHLENGTH+1];
	bool is_command;
	size_t jobs;
	size_t refcount;
};

struct pollfd *array;
struct builder *array_mirror;

size_t sz;
size_t servers;
size_t capacity;

void
grow_array()
{
	while (capacity <= sz) {
		if (capacity == 0)
			capacity = ARRAYINITSIZE;
		else
			capacity *= 2;
	}
	array = reallocarray(array, capacity, sizeof(struct pollfd));
	if (!array)
		errx(1, "out of memory");
}

#define ensure_array() do { if (sz == capacity) grow_array(); } while (0)

void
register_server(int s)
{
	ensure_array();
	array[sz++].fd = s;
}

void 
create_local_server(const char *name)
{
	struct sockaddr_un addr;
	int s;

	addr.sun_len = sizeof(addr);
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, name, sizeof(addr.sun_path));

	s = socket(AF_UNIX, SOCK_STREAM, 0);

	if (bind(s, (const struct sockaddr *)&addr, sizeof(addr)) == -1)
		errx(1, "couldn't bind %s", name);

	register_server(s);
}

void
create_inet_server(const char *server, const char *service)
{
	struct addrinfo hints, *res, *res0;
	int error;
	int s;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	error = getaddrinfo(server, service, &hints, &res0);
	if (error)
		errx(1, "%s", gai_strerror(error));

	for (res = res0; res; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1)
			continue;
		if (bind(s, res->ai_addr, res->ai_addrlen) == -1) {
			close(s);
			continue;
		}
		register_server(s);
	}
}

void
create_servers(const char *name)
{
	if (strchr(name, '/')) {
		create_local_server(name);
	} else {
		char *pos = strchr(name, ':');
		if (pos != NULL) {
			size_t len = pos-name;
			char *server = malloc(len+1);
			if (!server)
				err(1, "out of memory");
			memcpy(server, name, len);
			server[len] = 0;
			create_inet_server(server, pos+1);
			free(server);
		} else {
			create_inet_server(name, 0);
		}
	}
}

char *
genhash()
{
	unsigned char binary[HASHLENGTH/2];
	size_t i;
	char *r = malloc(HASHLENGTH+1);

	arc4random_buf(binary, sizeof(binary));
	for (i = 0; i != HASHLENGTH; i++) {
		r[i] = "0123456789abcdef"
		    [i % 2 == 0 ? (binary[i/2] & 0xf) : (binary[i/2] >>4U)];
	}
	r[i] = 0;
	return r;
}


int
main(int argc, char *argv[])
{
	int i;

	if (argc < 2)
		errx(1, "usage: build-control socketaddr...");
	for (i = 1; i != argc; i++)
		create_servers(argv[i]);

	servers = sz;

	printf("Hash token is %s\n", genhash());
}


