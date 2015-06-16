CC = llvm-gcc
CFLAGS = -Wall $(INCLUDES) -std=c11
LDFLAGS = -L.

default: salsa20.dylib

salsa20.dylib:
	$(CC) $(CFLAGS) -shared -Wall -o $@ salsa20.c

.PHONY: clean
clean:
	rm -f *.dylib
