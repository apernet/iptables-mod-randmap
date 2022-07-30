CFLAGS			?= -O2 -Wall 
CFLAGS			+= -I../include
XTABLES_SO_DIR	?= $(shell pkg-config xtables --variable xtlibdir)

.PHONY: all install uninstall clean

all: libxt_RANDMAP.so

install: libxt_RANDMAP.so
	install -Dm644 libxt_RANDMAP.so "${XTABLES_SO_DIR}/libxt_RANDMAP.so"

uninstall:
	rm -f "${XTABLES_SO_DIR}/libxt_RANDMAP.so"

clean:
	rm -f *.o *.so

libxt_RANDMAP.so: libxt_RANDMAP.o
	gcc -shared -fPIC -o $@ $^;

libxt_RANDMAP.o: libxt_RANDMAP.c
	gcc ${CFLAGS} -D_INIT=libxt_RANDMAP_init -fPIC -c -o $@ $<;

