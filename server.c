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
#include <sys/stat.h>
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
#include <errno.h>

#define HASHLENGTH 24

#define ARRAYINITSIZE 64
#define HASHINITSIZE 64
#define BACKLOG 128


struct builder {
	char hash[HASHLENGTH+1];
	bool is_command;
	size_t jobs;
	size_t refcount;
};

struct fdstate {
	struct builder *builder;
};
struct pollfd *fd_array;
struct builder *builder_array;
struct fdstate *fd2state;

struct garray {
	size_t element_size;
	size_t size;
	size_t capacity;
	void *pointer;
} fds = {
	.element_size = sizeof(struct pollfd)
    }, builders = {
	.element_size = sizeof(struct builder)
    }, fd2s = {
	.element_size = sizeof(struct fdstate)
    };



size_t sz;
size_t servers;
size_t capacity;
size_t maxfd;

void *
may_grow_array(struct garray *a)
{
	if (a->capacity <= a->size) {
		if (a->capacity == 0)
			a->capacity = ARRAYINITSIZE;
		else while (a->capacity <= a->size)
			a->capacity *= 2;
		a->pointer = reallocarray(a->pointer, 
		    a->capacity, a->element_size);
	}
	if (!a->pointer)
		errx(1, "out of memory");
	return a->pointer;
}


void
register_server(int s)
{
	fd_array = may_grow_array(&fds);
	fd_array[sz++].fd = s;
}

void 
create_local_server(const char *name)
{
	struct sockaddr_un addr;
	int s;

	addr.sun_len = sizeof(addr);
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, name, sizeof(addr.sun_path));

	if (unlink(name) == -1 && errno != ENOENT)
		err(1, "can't remove %s", name);

	s = socket(AF_UNIX, SOCK_STREAM, 0);

	if (bind(s, (const struct sockaddr *)&addr, sizeof(addr)) == -1)
		errx(1, "couldn't bind %s", name);

	if (chmod(name, 0700) == -1)
		err(1, "can't chmod %s", name);
	if (listen(s, BACKLOG) == -1)
		err(1, "listen(%s)", name);

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
		if (listen(s, BACKLOG) == -1)
			err(1, "listen(%s)", server);
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


