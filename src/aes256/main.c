#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "aes256.h"
#include "common.h"

typedef enum {
    ENCRYPT_ECB,
    DECRYPT_ECB,
    ENCRYPT_CBC,
    DECRYPT_CBC,
} aes_mode_t;

static char *pad(char *, int *, int);
static int write_to_file(char *, char *, int);

// Should behave equivalently to:
// openssl aes-256-ecb -in skittles.png -out skittles.enc.expected -K $(hexdump -e '16/1 "%02x"' skittles.key)
// (with -d for decryption)
int main(int argc, char **argv) {
    if (argc-1 != 5) {
        fprintf(stderr, "usage: %s {enc,dec}-{ecb,cbc} <ivfile> <infile> <keyfile> <outfile>\n", argv[0]);
        return 1;
    }

    char *modestr, *ivpath, *inpath, *keypath, *outpath,
         *ivbuf, *inbuf, *keybuf, *outbuf;
    modestr = argv[1];
    ivpath = argv[2];
    inpath = argv[3];
    keypath = argv[4];
    outpath = argv[5];

    aes_mode_t mode;
    if (!strcmp(modestr, "enc-ecb")) {
        mode = ENCRYPT_ECB;
    } else if (!strcmp(modestr, "dec-ecb")) {
        mode = DECRYPT_ECB;
    } else if (!strcmp(modestr, "enc-cbc")) {
        mode = ENCRYPT_CBC;
    } else if (!strcmp(modestr, "dec-cbc")) {
        mode = DECRYPT_CBC;
    } else {
        fprintf(stderr, "please specify either enc or dec for first argument\n");
        return 1;
    }

    int encrypt = mode == ENCRYPT_ECB || mode == ENCRYPT_CBC;
    int cbc = mode == ENCRYPT_CBC || mode == DECRYPT_CBC;

    int in_len, key_len, iv_len;

    if (read_to_buf(keypath, &keybuf, &key_len) < 0) {
        return 1;
    }

    if (key_len != 32) {
        fprintf(stderr, "keyfile `%s' is not 256 bits!\n", keypath);
        free(keybuf);
        return 1;
    }

    if (read_to_buf(inpath, &inbuf, &in_len) < 0) {
        free(keybuf);
        return 1;
    }

    if (cbc) {
        if (read_to_buf(ivpath, &ivbuf, &iv_len) < 0) {
            free(keybuf);
            free(inbuf);
            return 1;
        }

        if (iv_len != BLOCK_SIZE) {
            fprintf(stderr, "IV `%s' is not %d bytes!\n", ivpath, BLOCK_SIZE);
            free(keybuf);
            return 1;
        }
    } else {
        ivbuf = NULL;
    }

    if (encrypt) {
        char *padbuf;
        if (!(padbuf = pad(inbuf, &in_len, BLOCK_SIZE))) {
            free(inbuf);
            free(keybuf);
            free(ivbuf);
            return 1;
        }
        inbuf = padbuf;
    }

    if (!(outbuf = calloc(1, in_len))) {
        perror("calloc");
        free(inbuf);
        free(keybuf);
        free(ivbuf);
        return 1;
    }

    // overall, these casts are probably the safest we could do anywhere
    // for anything
    int nblocks = in_len / BLOCK_SIZE;
    switch (mode) {
        case ENCRYPT_ECB:
            aes256_enc_ecb((uint8_t *)inbuf, (uint8_t *)keybuf, (uint8_t *)outbuf, nblocks);
            break;

        case DECRYPT_ECB:
            aes256_dec_ecb((uint8_t *)inbuf, (uint8_t *)keybuf, (uint8_t *)outbuf, nblocks);
            break;

        case ENCRYPT_CBC:
            aes256_enc_cbc((uint8_t *)ivbuf, (uint8_t *)inbuf, (uint8_t *)keybuf,
                           (uint8_t *)outbuf, nblocks);
            break;

        case DECRYPT_CBC:
            aes256_dec_cbc((uint8_t *)ivbuf, (uint8_t *)inbuf, (uint8_t *)keybuf,
                           (uint8_t *)outbuf, nblocks);
            break;
    }

    free(inbuf);
    free(keybuf);
    free(ivbuf);

    int write_size;
    if (encrypt) {
        write_size = in_len;
    } else if (in_len) { // DECRYPT
        // Read the last padded PKCS#5 byte
        write_size = in_len - outbuf[in_len - 1];
    } else { // DECRYPT and input length == 0
        write_size = 0;
    }

    if (write_to_file(outpath, outbuf, write_size) < 0) {
        free(outbuf);
        return 1;
    }

    free(outbuf);
    return 0;
}

// PKCS #5 padding
static char *pad(char *buf, int *len, int block_size) {
    int padded_len = *len + (block_size - (*len % block_size));

    char *padded;
    if (!(padded = realloc(buf, padded_len))) {
        perror("realloc");
        return NULL;
    }

    // PKCS #5 padding says to pad with bytes holding difference between
    // padded and unpadded size
    int fill = padded_len - *len;
    memset(padded + *len, fill, padded_len - *len);

    *len = padded_len;
    return padded;
}

static int write_to_file(char *path, char *buf, int len) {
    FILE *f;
    if (!(f = fopen(path, "w"))) {
        perror("fopen");
        return -1;
    }

    for (int i = 0; i < len; i++) {
        if (putc(buf[i], f) == EOF) {
            perror("putc");
            fclose(f);
            return -1;
        }
    }

    fclose(f);
    return 0;
}
