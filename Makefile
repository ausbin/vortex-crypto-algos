CFLAGS ?= -g -pedantic -pedantic -Wall -Werror -Wextra \
		  -Wstrict-prototypes -Wold-style-definition -Iinclude -std=c99 \
		  -D_GNU_SOURCE -O0
CC ?= gcc

SHA_BIN = sha256
SHA_DIR = src/$(SHA_BIN)
SHA_OBJ = $(patsubst %.c,%.o,$(wildcard $(SHA_DIR)/*.c))

AES_BIN = aes256
AES_DIR = src/$(AES_BIN)
AES_OBJ = $(patsubst %.c,%.o,$(wildcard $(AES_DIR)/*.c))

ALL_BIN = $(SHA_BIN) $(AES_BIN)
ALL_DEP = $(patsubst %.c,%.d,$(wildcard $(SHA_DIR)/*.c $(AES_DIR)/*.c))
ALL_OBJ = $(patsubst %.c,%.o,$(wildcard $(SHA_DIR)/*.c $(AES_DIR)/*.c))

.PHONY: all clean

all: $(SHA_BIN) $(AES_BIN)

-include $(ALL_DEP_FILES)

%.o: %.c
	$(CC) -MMD -c $(CFLAGS) $< -o $@

$(SHA_BIN): $(SHA_OBJ)
	$(CC) $(CFLAGS) $^ -o $@

$(AES_BIN): $(AES_OBJ)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rvf $(ALL_BIN) $(ALL_OBJ) $(ALL_DEP)
