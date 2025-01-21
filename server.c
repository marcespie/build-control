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

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define HASHLENGTH 24

#define ARRAYINITSIZE 64
#define HASHINITSIZE 64
#define BACKLOG 128


struct builder {
	char *hash;
	size_t jobs;
	size_t refcount;
};

struct fdstate {
	struct builder *builder;
	bool is_server;
	bool is_leggit;
};

struct pollfd *fd_array;
struct builder **builder_array;
struct fdstate **fd2state;

struct garray {
	size_t element_size;
	size_t size;
	size_t capacity;
	void *pointer;
} fds = {
	.element_size = sizeof(struct pollfd)
    }, builders = {
	.element_size = sizeof(struct builder *)
    }, fd2s = {
	.element_size = sizeof(struct fdstate *)
    };

bool debug;

void *
may_grow_array(struct garray *a)
{
	if (a->capacity <= a->size) {
		size_t old = a->capacity;
		if (a->capacity == 0)
			a->capacity = ARRAYINITSIZE;
		else while (a->capacity <= a->size)
			a->capacity *= 2;
		a->pointer = recallocarray(a->pointer, old, 
		    a->capacity, a->element_size);
	}
	if (!a->pointer)
		errx(1, "out of memory");
	return a->pointer;
}

void *
emalloc(size_t sz)
{
	void *p = malloc(sz);
	if (!p)
		errx(1, "out of memory");
	return p;
}

char *
genhash(void)
{
	unsigned char binary[HASHLENGTH/2];
	size_t i;
	char *r = emalloc(HASHLENGTH+1);

	arc4random_buf(binary, sizeof(binary));
	for (i = 0; i != HASHLENGTH; i++) {
		r[i] = "0123456789abcdef"
		    [i % 2 == 0 ? (binary[i/2] & 0xf) : (binary[i/2] >>4U)];
	}
	r[i] = 0;
	return r;
}

size_t
new_builder(void)
{
	struct builder *b;
	size_t i;
	builder_array = may_grow_array(&builders);

	b = emalloc(sizeof(struct builder));
	b->hash = genhash();
	b->jobs = 0;
	b->refcount = 0;
	for (i = 0; i != builders.capacity; i++)
		if (!builder_array[i])
			break;
	builder_array[i] = b;
	if (i+1 > builders.size)
		builders.size = i+1;

	return i;
}

struct fdstate *
new_fdstate(int fd)
{
	struct fdstate *state;

	fd_array = may_grow_array(&fds);
	fd_array[fds.size].fd = fd;
	fd_array[fds.size++].events = POLLIN|POLLHUP;

	if (fd2s.size < fd)
		fd2s.size = fd;
	fd2state = may_grow_array(&fd2s);

	state = emalloc(sizeof(struct fdstate));

	fd2state[fd] = state;

	return state;
}

void
usage(void)
{
	fprintf(stderr, "Usage: build-server [-d] socket ...\n");
	exit(0);
}

void
register_server(int s)
{
	struct fdstate *state;

	state = new_fdstate(s);
	state->is_server = true;
	state->builder = NULL;
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

void
gc(int fd)
{
}

char *
retrieve_line(int fd)
{
	ssize_t n;
	static char buffer[1024];
	char *result;

	n = read(fd, buffer, sizeof buffer - 1);
	if (n < 2)
		return NULL;
	buffer[n] = 0;
	while (n > 0 && strchr("\r\n \t", buffer[n-1]))
		buffer[--n] = 0;
	result = buffer;
	while (strchr("\t ", *result))
		result++;
	return result;
}

ssize_t
find_builder(char *id)
{
	char *end;
	long l = strtol(id, &end, 10);

	if (l >= builders.size || l < 0)
		return -1;
	return l;
}

void
dispatch_new_jobs(struct builder *b, char *jobs)
{
	char buffer[1024];
	int n;
	size_t i;

	n = snprintf(buffer, sizeof buffer, "%s\r\n", jobs);
	for (i = 0; i != fds.size; i++) {
		int s = fd_array[i].fd;
		if (fd2state[s]->builder == b)
			write(s, buffer, n);
	}
}

void
handle_event(int fd, int events)
{
	struct fdstate *state;
	struct builder *b;
	ssize_t number;

	state = fd2state[fd];

	if (state->is_server) {
		if (debug)
			printf("Server connection\n");
		struct sockaddr_storage addr;
		socklen_t len = sizeof(addr);
		struct fdstate *state2;

		int s = accept(fd, (struct sockaddr *)&addr, &len);

		state2 = new_fdstate(s);
		state2->builder = NULL;
		state2->is_server = false;
		state2->is_leggit = false;
	} else if (!state->is_leggit) {
		if (debug)
			printf("Line from client\n");
		char *line = retrieve_line(fd);
		if (!line)
			goto error;
		char *dash = strchr(line, '-');
		if (!dash) 
			goto error;
		*dash = 0;
		number = find_builder(line);
		if (number == -1)
			goto error;
		b = builder_array[number];
		if (!b)
			goto error;
		if (strcmp(dash+1, b->hash) != 0)
			goto error;
		state->builder = b;
		state->is_leggit = true;
		if (debug)
			printf("Connection registered\n");
	} else if (state->builder == builder_array[0]) {
		int fdout = fd == 0 ? 1 : fd;
		char *line = retrieve_line(fd);
		if (strcmp(line, "new") == 0) {
			char buffer[1024];
			number = new_builder();
			b = builder_array[number];
			write(fdout, buffer, 
			    snprintf(buffer, sizeof buffer, "%zd-%s\n",
				number, b->hash));
		} else if (strcmp(line, "quit") == 0) {
			if (fdout == 1)
				exit(0);
			gc(fd);
		} else {
			char *pos = strchr(line, ':');
			if (!pos)
				return;
			*pos = 0;
			number = find_builder(line);
			if (number != -1)
				printf("Found builder %zd\n", number);
			else  {
				printf("Builder not found\n");
				return;
			}
			b = builder_array[number];
			dispatch_new_jobs(b, pos+1);
		}
	}
	return;
error:
	close(fd);
	gc(fd);
	exit(1);
}

int
main(int argc, char *argv[])
{
	int i;
	struct fdstate *state;
	int ch;
	ssize_t number;

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch(ch) {
		case 'd':
			debug = true;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		errx(1, "usage: build-control socketaddr...");
	for (i = 0; i != argc; i++)
		create_servers(argv[i]);

	number = new_builder();
	state = new_fdstate(0);
	state->is_server = false;
	state->is_leggit = true;
	state->builder = builder_array[number];

	printf("0-%s to connect\n", state->builder->hash);

	while (1) {
		size_t j;
		int n = poll(fd_array, fds.size, INFTIM);

		if (n == -1)
			err(1, "poll");
		for (j = 0; j != fds.size; j++) {
			if (fd_array[j].revents == 0)
				continue;
			handle_event(fd_array[j].fd, fd_array[j].revents);

			if (--n == 0)
				break;
		}
	}
}


