#!/bin/bash

[[ $# -ne 1 ]] && {
    printf 'usage: %s <test>\n' "$0" >&2
    printf '\n' >&2
    printf 'try %s skittles.png\n' "$0" >&2
    exit 1
}

test=$1

[[ ! -f tests/$test || ! -f tests/$test.key ]] && {
    printf 'could not locate test %s in tests/\n' "$test" >&2
    exit 1
}

printf 'testing %s...\n' "$test"

pushd tests >/dev/null
    key=$(hexdump -e '16/1 "%02x"' "$test.key")
    openssl aes-256-ecb -in "$test" -out "$test.enc.want" -K "$key"
    ../aes256 enc "$test" "$test.key" "$test.enc.got"

    if cmp "$test.enc."{got,want}; then
        printf '✅ encryption passed\n'
    else
        printf '🙏 encryption failed, start praying son\n'
        printf 'expected:\n'
        xxd "$test.enc.want" | head
        printf 'actual:\n'
        xxd "$test.enc.got" | head
    fi

    ../aes256 dec "$test.enc.got" "$test.key" "$test.dec"

    if cmp "$test"{,.dec}; then
        printf '✅ decryption passed\n'
    else
        printf '🙏 decryption failed, start praying son\n'
        printf 'expected:\n'
        xxd "$test" | head
        printf 'actual:\n'
        xxd "$test.dec" | head
    fi
popd >/dev/null
