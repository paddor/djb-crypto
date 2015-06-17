#include "test.h"
#define KEY_BYTES 32
#define SALSA20_ROUNDS 20

static unsigned char msg[] = "This is my message. It will be encoded.";

void hexDump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        fprintf (stderr, "%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                fprintf (stderr, "  %s\n", buff);

            // Output the offset.
            fprintf (stderr, "  %04x ", i);
        }

        // Now the hex code for the specific character.
        fprintf (stderr, " %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        fprintf (stderr, "   ");
        i++;
    }

    // And print the final ASCII bit.
    fprintf (stderr, "  %s\n", buff);
}


void get_random_key(unsigned char *k) {
  unsigned int to_read = KEY_BYTES;
  FILE *random = fopen("/dev/random", "r");
  assert(random && "couldn't open source of randomness");
  while (to_read > 0)
    to_read -= fread(k, sizeof(*k), to_read, random);
  fclose(random);
  hexDump("Random key", k, KEY_BYTES);
}

void get_random_nonce(uint64_t *nonce) {
  FILE *random = fopen("/dev/random", "r");
  while(!fread(nonce, sizeof(*nonce), 1, random));
  fclose(random);
}

int main(int argc, const char *argv[]) {
  unsigned char key[KEY_BYTES];
  unsigned char *ct;
  uint64_t nonce;

  printf("sizeof(msg): %lu\n", sizeof(msg));

  ct = malloc(sizeof(msg));
  assert(ct);

  get_random_key(key);
  get_random_nonce(&nonce);
  hexDump("nonce", &nonce, sizeof(nonce));

    salsa20_hash_xor(key, nonce, sizeof(msg), msg, ct);
  hexDump("plain text", msg, sizeof(msg));
  hexDump("cipher text", ct, sizeof(msg));

  free(ct);
}
