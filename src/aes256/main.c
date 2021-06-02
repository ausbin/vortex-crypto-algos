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
    ENCRYPT_CTR,
    DECRYPT_CTR,
} aes_mode_t;

static int tablegen(void);
static char *pad(char *, int *, int);
static char *zeropad(char *, int *, int);
static int write_to_file(char *, char *, int);

// Should behave equivalently to:
// openssl aes-256-ecb -in skittles.png -out skittles.enc.expected -K $(hexdump -e '16/1 "%02x"' skittles.key)
// (with -d for decryption)
int main(int argc, char **argv) {
    int do_tablegen = 0;
    int args_ok = 0;
    if (argc-1 >= 1) {
        do_tablegen = !strcmp(argv[1], "tablegen");
        args_ok = ((do_tablegen && argc-1 == 1) || (!do_tablegen && argc-1 == 5));
    }

    if (!args_ok) {
        fprintf(stderr, "usage: %s {enc,dec}-{ecb,cbc,ctr} <ivfile> <infile> <keyfile> <outfile>\n"
                        "       %s tablegen\n",
                argv[0], argv[0]);
        return 1;
    }

    if (do_tablegen) {
        return tablegen();
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
    } else if (!strcmp(modestr, "enc-ctr")) {
        mode = ENCRYPT_CTR;
    } else if (!strcmp(modestr, "dec-ctr")) {
        mode = DECRYPT_CTR;
    } else {
        fprintf(stderr, "please specify enc, dec, or tablegen for first argument\n");
        return 1;
    }

    int pad_input = mode == ENCRYPT_ECB || mode == ENCRYPT_CBC;
    int streaming = mode == ENCRYPT_CTR || mode == DECRYPT_CTR;
    int need_iv = mode == ENCRYPT_CBC || mode == DECRYPT_CBC
                  || mode == ENCRYPT_CTR || mode == DECRYPT_CTR;

    int in_len, key_len, iv_len, prepad_len;

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

    if (need_iv) {
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

    if (pad_input) {
        char *padbuf;
        prepad_len = in_len;
        if (!(padbuf = pad(inbuf, &in_len, BLOCK_SIZE))) {
            free(inbuf);
            free(keybuf);
            free(ivbuf);
            return 1;
        }
        inbuf = padbuf;
    } else if (streaming) {
        char *zeropadbuf = NULL;
        prepad_len = in_len;
        // Subtle: with an empty input, inbuf is NULL
        if (inbuf && !(zeropadbuf = zeropad(inbuf, &in_len, BLOCK_SIZE))) {
            free(inbuf);
            free(keybuf);
            free(ivbuf);
            return 1;
        }
        inbuf = zeropadbuf;
    } else {
        prepad_len = in_len;
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

        case ENCRYPT_CTR:
        case DECRYPT_CTR:
            aes256_ctr((uint8_t *)ivbuf, (uint8_t *)inbuf, (uint8_t *)keybuf,
                       (uint8_t *)outbuf, nblocks);
            break;
    }

    free(inbuf);
    free(keybuf);
    free(ivbuf);

    int write_size;
    if (streaming) {
        write_size = prepad_len;
    } else if (pad_input) {
        write_size = in_len;
    } else if (in_len) { // decrypt
        // Read the last padded PKCS#5 byte
        write_size = in_len - outbuf[in_len - 1];
    } else { // decrypt and input length == 0
        write_size = 0;
    }

    if (write_to_file(outpath, outbuf, write_size) < 0) {
        free(outbuf);
        return 1;
    }

    free(outbuf);
    return 0;
}

static int tablegen(void) {
    printf("#include \"tables.h\"\n\n");

    for (int dec = 0; dec < 2; dec++) {
        for (int table_num = 0; table_num < 4; table_num++) {
            printf("const uint8_t T%d_%s[256][4] = {\n", table_num, dec? "inv" : "fwd");

            for (int byte = 0; byte < 256; byte++) {
                uint8_t entries[4];
                if (dec) {
                    get_inv_table_entry(table_num, byte, entries);
                } else {
                    get_fwd_table_entry(table_num, byte, entries);
                }
                printf("%s{0x%02x, 0x%02x, 0x%02x, 0x%02x},%s",
                       (byte % 4)? "" : "    ",
                       entries[0], entries[1], entries[2], entries[3],
                       ((byte + 1) % 4)? " " : "\n");
            }

            printf("};\n\n");
        }
    }

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

static char *zeropad(char *buf, int *len, int block_size) {
    if (!(*len % block_size)) {
        // Already in good shape
        return buf;
    }

    int padded_len = *len + (block_size - (*len % block_size));

    char *padded;
    if (!(padded = realloc(buf, padded_len))) {
        perror("realloc");
        return NULL;
    }

    memset(padded + *len, 0, padded_len - *len);

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
