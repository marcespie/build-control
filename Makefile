PROG = build-server
CFLAGS = $(OPT) $(WARN) $(DEBUG)
OPT = -O2
WARN = -Wall
DEBUG =

DEST =

SRCS = build-server.c
OBJS = ${SRCS:.c=.o}

BINMODE = 0555
BINDIR = /usr/local/bin
MANDIR = /usr/local/man

all:	${PROG}

install: ${PROG}
	install -m ${BINMODE} build-server ${DESTDIR}${BINDIR}
	install -m ${BINMODE} build-server.1 ${DESTDIR}${MANDIR}/man1
	


clean:
	rm -f ${PROG} ${OBJS}
	
.PHONY: all install clean
