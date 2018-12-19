SHOBJ_CFLAGS ?= -fno-common -g -ggdb
SHOBJ_LDFLAGS ?= -shared -Bsymbolic
CFLAGS = -Wall -g -fPIC -lc -lm -Og -std=gnu99 -I.
CC=gcc

all: module.so

module.so: module.o
	$(LD) -o $@ module.o $(SHOBJ_LDFLAGS) $(LIBS) -lc -lpcre

clean:
	rm -f *.xo *.so *.o
