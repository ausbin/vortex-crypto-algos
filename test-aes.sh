#!/bin/bash

[[ $# -ne 2 ]] && {
    printf 'usage: %s cbc|ecb|ctr <test>\n' "$0" >&2
    printf '\n' >&2
    printf 'try %s skittles.png\n' "$0" >&2
    exit 1
}

mode=$1
test=$2

[[ ! -f tests/$test || ! -f tests/$test.key ]] && {
    printf 'could not locate test %s in tests/\n' "$test" >&2
    exit 1
}

printf 'testing %s with %s...\n' "$test" "$mode"

pushd tests >/dev/null
    key=$(hexdump -e '16/1 "%02x"' "$test.key")
    iv=$(hexdump -e '16/1 "%02x"' "$test.iv")
    openssl aes-256-$mode -in "$test" -out "$test.enc-$mode.want" -K "$key" -iv "$iv"
    ../aes256 enc-$mode "$test.iv" "$test" "$test.key" "$test.enc-$mode.got"

    if cmp "$test.enc-$mode."{got,want}; then
        printf '✅ encryption passed\n'
    else
        printf '🙏 encryption failed, start praying son\n'
        printf 'expected:\n'
        xxd "$test.enc-$mode.want" | head
        printf 'actual:\n'
        xxd "$test.enc-$mode.got" | head
    fi

    ../aes256 dec-$mode "$test.iv" "$test.enc-$mode.got" "$test.key" "$test.dec-$mode"

    if cmp "$test"{,.dec-$mode}; then
        printf '✅ decryption passed\n'
    else
        printf '🙏 decryption failed, start praying son\n'
        printf 'expected:\n'
        xxd "$test" | head
        printf 'actual:\n'
        xxd "$test.dec-$mode" | head
    fi
popd >/dev/null
