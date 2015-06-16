#include "poly1305.h"

// from http://cr.yp.to/mac/poly1305_gmp.c
void poly1305(
    const uint8_t r[16],
    const uint8_t s[16],
    size_t l,
    const uint8_t *m,
    uint8_t tag[16])
{
  unsigned int j;
  mpz_t rbar;
  mpz_t h;
  mpz_t c;
  mpz_t p;

  mpz_init(rbar);
  mpz_init(h);
  mpz_init(c);
  mpz_init(p);
  mpz_import(rbar,16,-1,1,0,0,r);
  mpz_set_ui(h,0);
  mpz_set_ui(p,1); mpz_mul_2exp(p,p,130); mpz_sub_ui(p,p,5);
  while (l > 0) {
    if (l < 16) j = l; else j = 16;
    mpz_import(c,j,-1,1,0,0,m);
    m += j; l -= j;
    mpz_add(h,h,c);
    mpz_set_ui(c,1); mpz_mul_2exp(c,c,8 * j); mpz_add(h,h,c);
    mpz_mul(h,h,rbar);
    mpz_tdiv_r(h,h,p);
  }
  mpz_import(c,16,-1,1,0,0,s);
  mpz_add(h,h,c);
  for (j = 0;j < 16;++j)
    tag[j] = mpz_tdiv_q_ui(h,h,256);
  mpz_clear(p);
  mpz_clear(c);
  mpz_clear(h);
  mpz_clear(rbar);
}

void poly1305_tag(
    const uint8_t key[32],
    const uint64_t aad_len,
    const uint8_t *aad,
    const uint64_t ct_len,
    const uint8_t *ct,
    uint8_t tag[16]) {

  uint8_t *md;
  size_t md_len = 0;
  size_t i = 0;
  int pad1, pad2;

  // allocate MAC data memory
  md_len += aad_len;
  pad1 = md_len % 16;
  md_len += pad1;
  md_len += ct_len;
  pad2 = md_len % 16;
  md_len += pad2;
  md_len += 16; // two uint64_t
  md = malloc(md_len * sizeof(uint8_t));

  // AAD
  memcpy(&md[i], aad, aad_len);
  i += aad_len;

  // first padding
  memset(&md[i], 0, pad1);
  i += pad1;

  // CT
  memcpy(&md[i], ct, ct_len);
  i += ct_len;

  // second padding
  memset(&md[i], 0, pad2);
  i += pad2;

  // AAD size as LE
  md[i++] = aad_len >> 56;
  md[i++] = aad_len >> 48;
  md[i++] = aad_len >> 40;
  md[i++] = aad_len >> 32;
  md[i++] = aad_len >> 24;
  md[i++] = aad_len >> 16;
  md[i++] = aad_len >>  8;
  md[i++] = aad_len >>  0;

  // CT size
  md[i++] = ct_len >> 56;
  md[i++] = ct_len >> 48;
  md[i++] = ct_len >> 40;
  md[i++] = ct_len >> 32;
  md[i++] = ct_len >> 24;
  md[i++] = ct_len >> 16;
  md[i++] = ct_len >>  8;
  md[i++] = ct_len >>  0;

  // calculate tag
  poly1305(&key[0], &key[16], md_len, md, tag);
}
