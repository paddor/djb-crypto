CC = llvm-gcc
INCLUDES =
CFLAGS = -Wall -std=c11
LDFLAGS = -L.

default: salsa20.dylib poly1305.dylib

crypto_box: crypto_box.h libcrypto.a crypto_box.c
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall -lcrypto -o $@ crypto_box.c

crypto_open: crypto_box.h libcrypto.a crypto_open.c
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall -lcrypto -o $@ crypto_open.c

test: test.c test.h libcrypto.a
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall -lcrypto -O0 -o $@ test.c
	./test

libcrypto.a: salsa20.o poly1305.o
	ar -r $@ salsa20.o poly1305.o

salsa20.o: salsa20.h salsa20.c
	$(CC) $(CFLAGS) -Wall -c -o $@ salsa20.c

poly1305.o: poly1305.h poly1305.c
	$(CC) $(CFLAGS) -Wall -c -o $@ poly1305.c

salsa20.dylib: salsa20.h salsa20.c
	$(CC) $(CFLAGS) -shared -Wall -o $@ salsa20.c

poly1305.dylib: poly1305.h poly1305.c
	$(CC) $(CFLAGS) -shared -Wall -o $@ poly1305.c

.PHONY: clean
clean:
	rm -f *.dylib
	rm -f *.o *.a test
