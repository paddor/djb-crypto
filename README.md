DjbCrypto
=========

DO NOT USE IN PRODUCTION! This is just an experiment for me to learn more about cryptography.

Even though these implementations should produce correct results, they
still don't provide high security because of possible side-channel attacks. So
"offline" usage should be okay, but still. I'm by no means a cryptography
expert.

If you're interested in using any of these primitives or sane combinations
of them in Ruby, please refer to the excellent library [RbNaCl](https://github.com/cryptosphere/rbnacl).


Coding rules
------------
I tried to respect the coding rules from 
https://cryptocoding.net/index.php/Coding_rules

Good:

* most of them are already met by the design of the algorithms (rule 1, 2, 3, 4)
* I tried to keep the API as easy and safe as possible (rule 6, 7)
* only unsigned integers have been used in the C extensions (rule 8)
* Ruby's GC will clean secret data, the C extensions won't hold anything in memory (rule 11)
* for random data, the Ruby standard library's SecureRandom is used (rule 12)

Bad:

* I'm not going to verify the assembly code for this experiment (rule 5)
* I guess did use the same types for different things, duh? Rules are incomplete. (rule 9, 10)
