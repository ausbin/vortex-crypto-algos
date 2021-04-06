This is my work for the implementations of AES-256 and SHA-256 for
<https://github.gatech.edu/aadams80/cs7290-vortex-crypto>.

AES
---
The specific form of AES implemented here is:

 * 256-bit key
 * PKCS#5 padding
 * Electronic Codebook (ECB): the cipher runs on each block
   independently (note this is not secure)

### Tests

I have been testing this implementation with the OpenSSL CLI. It was
getting tedious so I made a wrapper script `./test-aes.sh`. Available
tests `t` for `./test-aes.sh t`:

 * `zeroes16`: 16 bytes (a single AES block) of zeroes
 * `zeroes17`: 17 bytes (one more than a single AES block) of zeroes
 * `zeroes32`: 32 bytes (two AES blocks) of zeroes
 * `skittles.png`: A ~20KiB picture of the most important contribution
   the British have made to humanity

Note that each of these will get PKCS#5 padded, so the output will be up
to 16 bytes larger than the input.
