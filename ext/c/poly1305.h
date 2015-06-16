#include <inttypes.h>
#include <stddef.h>
#include <gmp.h>

void poly1305_tag(
    const uint8_t r[16],
    const uint8_t s[16],
    size_t l,
    const uint8_t *m,
    uint8_t tag[16]);
