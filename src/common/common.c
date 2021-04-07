#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

int read_to_buf(char *path, char **buf_out, int *len_out) {
    FILE *f;
    if (!(f = fopen(path, "r"))) {
        perror("fopen");
        return -1;
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
                return -1;
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
        return -1;
    }

    *len_out = buf_len;
    *buf_out = buf;

    fclose(f);
    return 0;
}

