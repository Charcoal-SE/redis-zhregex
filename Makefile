SHOBJ_CFLAGS ?= -fno-common -g -ggdb
SHOBJ_LDFLAGS ?= -shared -Bsymbolic
LDFLAGS = -lc -lpcre
GCCFLAGS = -Wall -Wextra -g -fPIC -shared -lc -lm -Og -std=gnu99 -I.
DISABLED_WARNINGS =  -Wno-unused-parameter
CLANGFLAGS = -g -fPIC -shared -std=gnu99 -I. -Wall -Wextra $(DISABLED_WARNINGS)
CC=clang

ifeq ($(CC),clang)
  CFLAGS = $(CLANGFLAGS)
else ifeq ($(CC),gcc)
	CFLAGS = $(GCCFLAGS)
endif

# all: module

module.so: module.c
	$(CC) -o $@ module.c $(CFLAGS) $(LDFLAGS)

clean:
	rm -f *.xo *.so *.o
