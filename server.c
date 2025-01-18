#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
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
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int 
create_local_server(const char *name)
{
	struct sockaddr_un addr;
	int s;

	addr.sun_len = sizeof(addr);
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, name, sizeof(addr.sun_path));

	s = socket(AF_UNIX, SOCK_STREAM, 0);

	if (bind(s, (const struct sockaddr *)&addr, sizeof(addr)) == -1)
		errx(1, "coulnd't bind %s", name);

	return s;
}

int
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
	}
	if (s == -1)
		errx(1, "couldn't bind server for %s", server);
	return s;
}

int
create_server(const char *name)
{
	int fd = -1;
	if (strchr(name, '/')) {
		fd = create_local_server(name);
	} else {
		char *pos = strchr(name, ':');
		if (pos != NULL) {
			size_t len = pos-name;
			char *server = malloc(len+1);
			if (!server)
				err(1, "out of memory");
			memcpy(server, name, len);
			server[len] = 0;
			fd = create_inet_server(server, pos+1);
			free(server);
		} else {
			fd = create_inet_server(name, 0);
		}
	}
	return fd;
}



int
main(int argc, char *argv[])
{
	if (argc != 2)
		errx(1, "usage: build-control socketaddr");
	int fd = create_server(argv[1]);


}
