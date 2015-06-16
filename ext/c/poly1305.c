#include "poly1305.h"

// from http://cr.yp.to/mac/poly1305_gmp.c
void poly1305_tag(
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
