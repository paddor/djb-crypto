#include <inttypes.h>
#include <stddef.h>
#include <gmp.h>
#include <string.h>
#include <stdlib.h>

void poly1305(
    const uint8_t r[16],
    const uint8_t s[16],
    size_t l,
    const uint8_t *m,
    uint8_t tag[16]);

void poly1305_tag(
    const uint8_t key[32],
    const uint64_t aad_len,
    const uint8_t *aad,
    const uint64_t ct_len,
    const uint8_t *ct,
    uint8_t tag[16]);
