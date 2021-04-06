#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "aes256.h"

static char *read_to_buf(char *, int *);
static char *pad(char *, int *, int);
static int write_to_file(char *, char *, int);

// Should behave equivalently to:
// openssl aes-256-ecb -in skittles.png -out skittles.enc.expected -K $(hexdump -e '16/1 "%02x"' skittles.key)
int main(int argc, char **argv) {
    if (argc-1 != 3) {
        fprintf(stderr, "usage: %s <infile> <keyfile> <outfile>\n", argv[0]);
        return 1;
    }

    char *inpath, *keypath, *outpath,
         *inbuf, *keybuf, *outbuf;
    inpath = argv[1];
    keypath = argv[2];
    outpath = argv[3];

    int in_len, key_len;

    if (!(keybuf = read_to_buf(keypath, &key_len))) {
        return 1;
    }

    if (key_len != 32) {
        fprintf(stderr, "keyfile `%s' is not 256 bits!\n", keypath);
        free(keybuf);
        return 1;
    }

    if (!(inbuf = read_to_buf(inpath, &in_len))) {
        free(keybuf);
        return 1;
    }

    char *padbuf;
    if (!(padbuf = pad(inbuf, &in_len, BLOCK_SIZE))) {
        free(inbuf);
        free(keybuf);
        return 1;
    }
    inbuf = padbuf;

    if (!(outbuf = calloc(1, in_len))) {
        perror("calloc");
        free(inbuf);
        free(keybuf);
        return 1;
    }

    // overall, these casts are probably the safest we could do anywhere
    // for anything
    aes256((uint8_t *)inbuf, (uint8_t *)keybuf, (uint8_t *)outbuf, in_len / BLOCK_SIZE);

    free(inbuf);
    free(keybuf);
    if (write_to_file(outpath, outbuf, in_len) < 0) {
        free(outbuf);
        return 1;
    }

    free(outbuf);
    return 0;
}

static char *read_to_buf(char *path, int *len_out) {
    FILE *f;
    if (!(f = fopen(path, "r"))) {
        perror("fopen");
        return NULL;
    }

    int buf_cap = 0, buf_len = 0;
    char *buf = NULL;
    int c;
    errno = 0;
    while ((c = getc(f)) != EOF) {
        if (buf_len == buf_cap) {
            buf_cap = (buf_cap + 1) * 2;
            char *new_buf;
            if (!(new_buf = realloc(buf, buf_cap))) {
                perror("realloc");
                free(buf);
                fclose(f);
            }
            buf = new_buf;
        }

        buf[buf_len] = c;
        buf_len++;
    }
    if (errno) {
        perror("getc");
        free(buf);
        fclose(f);
        return NULL;
    }

    *len_out = buf_len;

    fclose(f);
    return buf;
}

// PKCS #5 padding
static char *pad(char *buf, int *len, int block_size) {
    if (!(*len % BLOCK_SIZE)) {
        return buf;
    }

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
