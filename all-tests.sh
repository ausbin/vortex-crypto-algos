#!/bin/bash

printf 'Testing AES-256...\n'
for keyfile in tests/*.key; do
    test=$(basename ${keyfile%.key})
    ./test-aes.sh ecb "$test"
    ./test-aes.sh cbc "$test"
    ./test-aes.sh ctr "$test"
done

printf '\nTesting SHA-256...\n'
for keyfile in tests/*.key; do
    test=$(basename ${keyfile%.key})
    ./test-sha.sh "$test"
done
