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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>

#if !defined(__OpenBSD__)

/* straight from OpenBSD libc, this piece of code is:
 *
 * Copyright (c) 2008, 2017 Otto Moerbeek <otto@drijf.net>
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
/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#define MUL_NO_OVERFLOW ((size_t)1 << (sizeof(size_t) * 4))

void *recallocarray(void *, size_t, size_t, size_t);

void *
recallocarray(void *ptr, size_t oldnmemb, size_t newnmemb, size_t size)
{
	size_t oldsize, newsize;
	void *newptr;

	if (ptr == NULL)
		return calloc(newnmemb, size);

	if ((newnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < size) {
		errno = ENOMEM;
		return NULL;
	}
	newsize = newnmemb * size;

	if ((oldnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < size) {
		errno = EINVAL;
		return NULL;
	}
	oldsize = oldnmemb * size;

	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	if (newsize <= oldsize) {
		size_t d = oldsize - newsize;

		if (d < oldsize / 2 && d < (size_t)getpagesize()) {
			memset((char *)ptr + newsize, 0, d);
			return ptr;
		}
	}

	newptr = malloc(newsize);
	if (newptr == NULL)
		return NULL;

	if (newsize > oldsize) {
		memcpy(newptr, ptr, oldsize);
		memset((char *)newptr + oldsize, 0, newsize - oldsize);
	} else
		memcpy(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	free(ptr);

	return newptr;
}
#endif

bool debug;
char *setuser;

#define HASHLENGTH 24

#define ARRAYINITSIZE 64
#define BACKLOG 128
#define SOCKETBUFSIZE 1024

/* For linux */
#define RANDOM_DEVICE "/dev/random"


/* rather straightforward data structures:
 * each build program is represented by a builder
 * containing the id hash, and the corresponding
 * jobs number + count of instances
 */
struct builder {
	char *hash;
	long jobs;
	size_t refcount;
};

/* this is all stored in a builder array, and
 * the index is used for the initial connection
 * e.g., index-hash is the identification string
 */
struct builder **builder_array;

/* Note that builder_array[0] is not a real job
 * but rather the identifier for any external entity
 * wanting to control jobs (e.g., through nc -U usually)
 */


/* now fds are stored in a pollfd, as is traditional.
 * where we do move stuff around when fd gets garbage
 * collected.
 */
struct pollfd *fd_array;

/* The whole correspondance fd -> builder is directly
 * indexed by the fd.
 * We have a bit of state, as initially the connection
 * is unrelated to any builder, and then to distinguish
 * the actual server sockets
 */
struct fdstate {
	long builder_idx;
	bool is_server;
	bool is_leggit;
};

struct fdstate **state_array;

/* all these three arrays will grow as needed, using
 * basic size/capacity idioms. Note we rely on 0 initialization.
 */
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


void *may_grow_array(struct garray *);
void *emalloc(size_t);
char *genhash(void);
void fdprintf(int, const char *, ...);
size_t new_builder(void);
struct fdstate *new_fdstate(int);
void usage();
void register_server(int);
void create_local_server(const char *);
void create_inet_server(const char *, const char *);
void create_servers(const char *);
void gc(size_t, int);
char *retrieve_line(int);
ssize_t find_builder_idx(const char *);
void dispatch_new_jobs(struct builder *, const char *);
void setup_new_connection(int, int);
void authentify_connection(size_t, int, int, struct fdstate *);
void dump(int);
void handle_control_message(size_t, int, int);
void handle_event(size_t, int, int);
void dropprivs(void);

/* So basically: both state_array and builder_array will
 * have holes (which is okay because null pointers)
 * but pollfd is always fully populated, as required for poll(2)
 */

/* Always ensures there's at least one free slot at the end of array.
 * Since this is "generic programming" in C we avoid unsightly casts by using
 * actual_array = may_grow_array(&garray_info);
 * .e.g., state_array = may_grow_array(&fd2s);
 * XXX the way this works, we can set size arbitrarily, and call
 * may_grow_array to get capacity to match
 */
void *
may_grow_array(struct garray *a)
{
	if (a->capacity <= a->size) {
		size_t old = a->capacity;
		if (a->capacity == 0)
			a->capacity = ARRAYINITSIZE;
		else while (a->capacity <= a->size)
			a->capacity *= 2;
		/* note the use of recallocarray in order to have
		 * null pointers and the likes
		 */
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
	void *p;

	p = malloc(sz);
	if (!p)
		errx(1, "out of memory");
	return p;
}

char *
genhash(void)
{
	unsigned char binary[HASHLENGTH/2];
	size_t i;
	char *r;
#if defined(__linux__)
	int fd;
	ssize_t n;

	fd = open(RANDOM_DEVICE, O_RDONLY);
	if (fd == -1)
		err(1, "can't open dev/random");
	n = read(fd, binary, sizeof(binary));
	if (n == -1)
		err(1, "can't read random data from %s", RANDOM_DEVICE);
    	if (n != sizeof(binary))
		errx(1, "Short read of random data from %s", RANDOM_DEVICE);
#else
	arc4random_buf(binary, sizeof(binary));
#endif

	r = emalloc(HASHLENGTH+1);
	/* pretty obvious way to convert binary to hex string */
	for (i = 0; i != HASHLENGTH; i++) {
		r[i] = "0123456789abcdef"
		    [i % 2 == 0 ? (binary[i/2] & 0xf) : (binary[i/2] >>4U)];
	}
	r[i] = 0;
	return r;
}

void
fdprintf(int fd, const char *fmt, ...)
{
	char buffer[SOCKETBUFSIZE];
	va_list ap;
	int n;
	ssize_t k;

	va_start(ap, fmt);
	n = vsnprintf(buffer, sizeof buffer, fmt, ap);
	if (n < 0)
		err(1, "vnsprinf");
	if (n > sizeof buffer)
		errx(1, "bad use of fdprintf with a too large result");
	k = write(fd, buffer, n);
	if (k == -1)
		err(1, "write failed");
	else if (k != n)
		errx(1, "short write, shouldn't happen");
	va_end(ap);
}

/* XXX returning the index instead of the builder
 * allows us easy access to the index, instead of
 * having to store it inside the builder structure
 */
size_t
new_builder(void)
{
	struct builder *b;
	size_t i;

	b = emalloc(sizeof(struct builder));
	b->hash = genhash();
	b->jobs = -1;
	/* XXX builders will be gc'd when refcount reaches 0 again, except
	 * for builder 0.
	 */
	b->refcount = 0;
	for (i = 0; i != builders.capacity; i++)
		if (!builder_array[i])
			break;
	if (i+1 > builders.size)
		builders.size = i+1;

	builder_array = may_grow_array(&builders);

	builder_array[i] = b;

	return i;
}

struct fdstate *
new_fdstate(int fd)
{
	struct fdstate *state;

	fd_array = may_grow_array(&fds);
	fd_array[fds.size].fd = fd;
	fd_array[fds.size++].events = POLLIN|POLLHUP;

	if (fd2s.size < fd+1)
		fd2s.size = fd+1;
	state_array = may_grow_array(&fd2s);

	state = emalloc(sizeof(struct fdstate));
	state_array[fd] = state;

	return state;
}

void
usage(void)
{
	fprintf(stderr, "Usage: build-server [-d] [-u user] socket ...\n");
	exit(0);
}

void
register_server(int s)
{
	struct fdstate *state;

	state = new_fdstate(s);
	state->builder_idx = -1;
	state->is_server = true;
}

void 
create_local_server(const char *name)
{
	struct sockaddr_un addr;
	int s;

	addr.sun_family = AF_UNIX;
	if (strlen(name)+1 > sizeof(addr.sun_path))
		errx(1, "can't bind to %s: too long", name);
	strncpy(addr.sun_path, name, sizeof(addr.sun_path));

	if (unlink(name) == -1 && errno != ENOENT)
		err(1, "can't remove %s", name);

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s == -1)
		errx(1, "couldn't create socket");

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
		char *pos;
		pos = strchr(name, ':');
		if (pos != NULL) {
			size_t len;
			char *server;

			len = pos-name;
			server = emalloc(len+1);
			memcpy(server, name, len);
			server[len] = 0;
			create_inet_server(server, pos+1);
			free(server);
		} else {
			create_inet_server(name, 0);
		}
	}
}

/* Requires TWO parms because we need to know WHICH pollfd entry, otherwise
 * we would have to scan. */
void
gc(size_t j, int fd)
{
	struct fdstate *state;

	close(fd);
	/* just reorder the fd_array. Note that we will "miss" one
	 * potential event this loop but that's not a problem
	 */
	if (j != fds.size -1)
		fd_array[j].fd = fd_array[fds.size-1].fd;
	fds.size--;
	state = state_array[fd];
	state_array[fd] = NULL;

	if (state->builder_idx > 0) {
		struct builder *b;
		b = builder_array[state->builder_idx];
		b->refcount--;
		if (b->refcount == 0) {
			free(b);
			builder_array[state->builder_idx] = NULL;
		}
	}
	free(state);
}

/* retrieves line (from telnet-like protocol) and strips end-of-line, e.g., 
 * all \r\n\t spaces, along with starting spaces
 * XXX notice static storage, so overwritten each time retrieve_line is called.
 */
char *
retrieve_line(int fd)
{
	ssize_t n;
	static char buffer[SOCKETBUFSIZE];
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
find_builder_idx(const char *id)
{
	char *end;
	long l;

	l = strtol(id, &end, 10);
	if (l >= builders.size || l < 0)
		return -1;
	return l;
}

void
dispatch_new_jobs(struct builder *b, const char *jobs)
{
	size_t i;
	char *end;
	long l;

	l = strtol(jobs, &end, 10);
	if (l < 0)
		return;
	b->jobs = l;

	for (i = 0; i != fds.size; i++) {
		int s = fd_array[i].fd;
		if (builder_array[state_array[s]->builder_idx] == b)
			fdprintf(s, "%ld\r\n", l);
	}
}

void
setup_new_connection(int fd, int events)
{
	struct sockaddr_storage addr;
	socklen_t len;
	struct fdstate *state;
	int s;

	if (debug)
		printf("Server connection\n");
	len = sizeof(addr);

	s = accept(fd, (struct sockaddr *)&addr, &len);

	state = new_fdstate(s);
	state->builder_idx = -1;
	state->is_server = false;
	state->is_leggit = false;
}

void
authentify_connection(size_t j, int fd, int events, struct fdstate *state)
{
	char *line;
	char *dash;
	ssize_t idx;
	struct builder *b;

	if (debug)
		printf("Line from client\n");
	line = retrieve_line(fd);
	if (!line)
		goto error;
	dash = strchr(line, '-');
	if (!dash) 
		goto error;
	*dash = 0;
	idx = find_builder_idx(line);
	if (idx == -1)
		goto error;
	b = builder_array[idx];
	if (!b)
		goto error;
	if (strcmp(dash+1, b->hash) != 0)
		goto error;
	state->builder_idx = idx;
	state->is_leggit = true;
	if (b->jobs != -1)
		fdprintf(fd, "%ld\r\n", b->jobs);
	if (debug)
		printf("Connection registered\n");
	b->refcount++;
	return;
error:
	gc(j, fd);
}

void
dump(int fdout)
{
	size_t idx;
	struct fdstate *s;
	struct builder *b;

	for (idx = 0; idx != fd2s.size; idx++) {
		s = state_array[idx];
		if (!s)
			continue;
		fdprintf(fdout, 
		    "fd %zu points to job #%ld (server %d/leggit %d)\n", 
		    idx, s->builder_idx, s->is_server, s->is_leggit);
	}
	for (idx = 0; idx != builders.size; idx++) {
		b = builder_array[idx];
		if (!b)
			continue;
		fdprintf(fdout, 
		    "Build number %zu, hash %s, jobcount %ld refs %zu\n",
		    idx, b->hash, b->jobs, b->refcount);
	}
}

void
handle_control_message(size_t j, int fd, int events)
{
	int fdout;
	char *line;
	ssize_t idx;
	char *pos;
	struct builder *b;

	fdout = fd == 0 ? 1 : fd;
	line = retrieve_line(fd);
	if (strcmp(line, "new") == 0) {
		idx = new_builder();
		fdprintf(fdout, "%zd-%s\n", idx, builder_array[idx]->hash);
	} else if (strcmp(line, "quit") == 0) {
		if (fdout == 1)
			exit(0);
		gc(j, fd);
    	} else if (strcmp(line, "dump") == 0) {
		dump(fdout);
	} else {
		pos = strchr(line, ':');
		if (!pos)
			return;
		*pos = 0;
		idx = find_builder_idx(line);
		if (idx == -1) {
			fdprintf(fdout, "Couldn't find builder %zd\n", idx);
			return;
		}
		b = builder_array[idx];
		if (!b)
			fdprintf(fdout, "%zd: no such builder\n", idx);
		else
			dispatch_new_jobs(b, pos+1);
	}
}

void
handle_event(size_t j, int fd, int events)
{
	struct fdstate *state;

	state = state_array[fd];

	if (events & POLLHUP) {
		gc(j, fd);
	} else if (state->is_server) {
		setup_new_connection(fd, events);
	} else if (!state->is_leggit) {
		authentify_connection(j, fd, events, state);
	} else if (state->builder_idx == 0) {
		handle_control_message(j, fd, events);
	}
}

void
dropprivs(void)
{
	struct passwd *pw;

	pw = getpwnam(setuser);

	if (!pw)	
		errx(1, "failed to find user %s", setuser);
	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
	    	err(1, "couldn't drop privileges");
}

int
main(int argc, char *argv[])
{
	int i;
	int ch;
	ssize_t idx;
	struct fdstate *state;
	int n;
	size_t j;

	while ((ch = getopt(argc, argv, "du:")) != -1) {
		switch(ch) {
		case 'd':
			debug = true;
			break;
		case 'u':
			setuser = optarg;
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

	if (setuser)
		dropprivs();
	idx = new_builder();
	state = new_fdstate(0);
	state->is_server = false;
	state->is_leggit = true;
	state->builder_idx = idx;

	printf("0-%s to connect\n", builder_array[idx]->hash);

	while (1) { /* classic poll loop */
#ifndef INFTIM	
#define INFTIM (-1)
#endif
		n = poll(fd_array, fds.size, INFTIM);

		if (n == -1)
			err(1, "poll");
		for (j = 0; j != fds.size; j++) {
			if (fd_array[j].revents == 0)
				continue;
			handle_event(j, fd_array[j].fd, fd_array[j].revents);

			if (--n == 0)
				break;
		}
	}
}
