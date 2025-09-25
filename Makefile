PROG = build-server
CFLAGS = $(OPT) $(WARN) $(DEBUG)
OPT = -O2
WARN = -Wall
DEBUG =

DEST =

SRCS = build.control.c
OBJS = ${SRCS:.c=.o}

BINMODE = 0555
BINDIR = /usr/local/bin

all:	${PROG}

install: ${PROG}
	install -m ${BINMODE} build-control ${DESTDIR}${BINDIR}/build-control
	


clean:
	rm -f ${PROG} ${OBJS}
	
.PHONY: all install clean
