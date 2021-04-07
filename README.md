This is my work for the implementations of AES-256 and SHA-256 for
<https://github.gatech.edu/aadams80/cs7290-vortex-crypto>.

AES
---
The specific form of AES implemented here is:

 * 256-bit key
 * PKCS#5 padding. Heads up, this can cause the encrypted output to be
   up to 16 bytes larger than the input
 * Electronic Codebook (ECB): the cipher runs on each block
   independently (note this is not secure)

SHA-256
-------

This is plane-jane SHA-256, except that it operates on a byte
granularity (e.g., you cannot get the checksum of the single bit `1`). I
do not think this is much of a limitation.

Tests
-----

I have been testing this implementation with the OpenSSL CLI as well as
`sha256sum` from the GNU coreutils. It was getting tedious so I made
some wrapper scripts: `./test-aes.sh` and `./test-sha.sh`. I also made
`./all-tests.sh` to run all the tests for both SHA and AES.

Available tests `t` for `./test-aes.sh t` or `./test-sha.sh t`:

 * `zeroes16`: 16 bytes (a single AES block) of zeroes
 * `zeroes17`: 17 bytes (one more than a single AES block) of zeroes
 * `zeroes32`: 32 bytes (two AES blocks) of zeroes
 * `skittles.png`: A ~20KiB picture of the most important contribution
   the British have made to humanity
 * `empty`: Empty file
 * `helloworld.txt`: the text `hello world` (no newline)

All the AES key files for these are 32 bytes and were generated with
`dd if=/dev/urandom bs=32 count=1 of=sometest.key`.
