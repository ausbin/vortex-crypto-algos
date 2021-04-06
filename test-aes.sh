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

pushd tests >/dev/null
    key=$(hexdump -e '16/1 "%02x"' "$test.key")
    openssl aes-256-ecb -in "$test" -out "$test.enc.want" -K "$key"
    ../aes256 "$test" "$test.key" "$test.enc.got"

    if cmp "$test.enc."{got,want}; then
        printf '✅ pass\n'
    else
        printf '🙏 start praying son\n'
        printf 'expected:\n'
        xxd "$test.enc.want" | head
        printf 'actual:\n'
        xxd "$test.enc.got" | head
    fi
popd >/dev/null
