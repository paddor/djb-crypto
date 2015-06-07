DjbCrypto
=========

DO NOT USE IN PRODUCTION! This is just an experiment for me to learn more about cryptography.

Even though these implementations should produce correct results, they
still don't provide high security because Ruby handles different sizes of
integers differently (Fixnum/Bignum), which might allow side-channel attacks (such as timing
attacks).

Furthermore, this code isn't fast at all, since it's pure Ruby.
If you're interested in using any of these primitives or sane combinations
of them in Ruby, please refer to the excellent library [RbNaCl](https://github.com/cryptosphere/rbnacl).
