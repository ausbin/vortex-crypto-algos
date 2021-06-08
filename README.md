These are my implementations of AES-256 and SHA-256 for
<https://github.com/ausbin/vortex/tree/crypto>. The idea is to test them
for correctness on a normal GNU/Linux system where we have gdb,
valgrind, etc., to avoid more difficult debugging once ported to Vortex
kernels.

AES
---
The specific form of AES implemented here is:

 * 256-bit key
 * PKCS#5 padding. Heads up, this can cause the encrypted output to be
   up to 16 bytes larger than the input. Note the actual Vortex kernels
   do not use this padding code as our actual benchmarks use
   block-aligned test data
 * [Cipher modes][1]: ECB, CBC, CTR

The initial implementation is based on a naïve reading of [the AES
specification][3], but I subsequently implemented the T-table approach
described in Section 4.2.1 of [*The Design of Rijndael* (2002)][2]. You
can swap between implementations by changing the `$(AES_IMPL)` value in
the Makefile to one of the following:

 * `TABLE`: Use separate tables T0, T1, T2, T3
 * `TABLE,MONOTABLE`: Use only T0, rotating the result to get T1, T2, T3
 * `ORIGINAL`: This is the original naïve implementation. The resulting
   `AES_ORIGINAL` macro isn't actually used; the important thing is the
   absence of `AES_TABLE`

Running `make tablegen` will regenerate the C file for the tables,
`src/aes256/tables.c`. Note it will not include the preprocessor
directives I have added by hand after generation, sorry

SHA-256
-------

This is plane-jane SHA-256, except that it operates on a byte
granularity (e.g., you cannot get the checksum of the single bit `1`). I
do not think this is much of a limitation.

Tests
-----

I have been testing this implementation with the OpenSSL CLI (for AES)
as well as `sha256sum` from the GNU coreutils. It was getting tedious so
I made some wrapper scripts: `./test-aes.sh` and `./test-sha.sh`. I also
made `./all-tests.sh` to run all the tests for both SHA and AES.

Available tests `t` for `./test-aes.sh ecb|cbc|ctr t` or `./test-sha.sh t`:

 * `zeroes16`: 16 bytes (a single AES block) of zeroes
 * `zeroes17`: 17 bytes (one more than a single AES block) of zeroes
 * `zeroes32`: 32 bytes (two AES blocks) of zeroes
 * `skittles.png`: A ~20KiB picture of the main source of my nutrition
 * `piazza.png`: A ~120KiB PNG of the logo of an Italian food website
 * `empty`: Empty file
 * `helloworld.txt`: the text `hello world` (no newline)

All the AES key files for these are 32 bytes and were generated with
`dd if=/dev/urandom bs=32 count=1 of=sometest.key`. The initialization
vectors were generated similarly, and are used as the IV for CBC and the
initial counter for CTR.

[1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Confidentiality_only_modes
[2]: https://link.springer.com/book/10.1007%2F978-3-662-04722-4
[3]: https://www.nist.gov/publications/advanced-encryption-standard-aes
