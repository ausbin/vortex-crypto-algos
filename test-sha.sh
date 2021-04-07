#!/bin/bash

[[ $# -ne 1 ]] && {
    printf 'usage: %s <test>\n' "$0" >&2
    printf '\n' >&2
    printf 'try %s skittles.png\n' "$0" >&2
    exit 1
}

test=$1

[[ ! -f tests/$test ]] && {
    printf 'could not locate test %s in tests/\n' "$test" >&2
    exit 1
}

printf 'testing %s...\n' "$test"

pushd tests >/dev/null
    expected=$(sha256sum "$test" | cut -d ' ' -f 1)
    actual=$(../sha256 "$test")

    if [[ $expected = $actual ]]; then
        printf '✅ hashes match passed\n'
    else
        printf '🙏 hash mismatch, start praying son\n'
        printf 'expected: %s\n' "$expected"
        printf 'actual: %s\n' "$actual"
    fi
popd >/dev/null
