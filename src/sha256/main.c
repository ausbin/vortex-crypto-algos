#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"
#include "common.h"

int main(int argc, char **argv) {
    if (argc-1 != 1) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 1;
    }

    char *buf;
    char *inpath = argv[1];
    int len;

    if (read_to_buf(inpath, &buf, &len) < 0) {
        return 1;
    }

    uint8_t *padded;
    if (!(padded = malloc(PADDED_SIZE_BYTES(len)))) {
        perror("malloc");
        free(buf);
        return 1;
    }
    memcpy(padded, buf, len);
    free(buf);

    uint8_t digest[DIGEST_BYTES];

    sha256(padded, len, digest);
    free(padded);

    for (int b = 0; b < DIGEST_BYTES; b++) {
        printf("%02x", digest[b]);
    }
    printf("\n");

    return 0;
}
