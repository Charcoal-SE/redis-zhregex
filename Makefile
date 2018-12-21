SHOBJ_CFLAGS ?= -fno-common -g -ggdb
SHOBJ_LDFLAGS ?= -shared -Bsymbolic
GCCFLAGS = -Wall -Wextra -g -fPIC -lc -lm -Og -std=gnu99 -I.
DISABLED_WARNINGS =  -Wno-unused-parameter
CLANGFLAGS = -g -fPIC -std=gnu99 -I. -Wall -Wextra $(DISABLED_WARNINGS)
CC=clang

ifeq ($(CC),clang)
  CFLAGS = $(CLANGFLAGS)
else ifeq ($(CC),gcc)
	CFLAGS = $(GCCFLAGS)
endif

all: module.so

module.so: module.o
	$(LD) -o $@ module.o $(SHOBJ_LDFLAGS) $(LIBS) -lc -lpcre

clean:
	rm -f *.xo *.so *.o
