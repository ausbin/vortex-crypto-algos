#!/bin/bash
exec valgrind --leak-check=full --error-exitcode=1 --show-leak-kinds=all --errors-for-leak-kinds=all "$@"
