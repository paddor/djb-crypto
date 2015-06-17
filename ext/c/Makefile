CC = llvm-gcc
CFLAGS = -Wall $(INCLUDES) -std=c11
LDFLAGS = -L.

default: salsa20.dylib poly1305.dylib

salsa20.dylib: salsa20.h salsa20.c
	$(CC) $(CFLAGS) -shared -Wall -o $@ salsa20.c

poly1305.dylib: poly1305.h poly1305.c
	$(CC) $(CFLAGS) -shared -Wall -o $@ poly1305.c

.PHONY: clean
clean:
	rm -f *.dylib
