#!/bin/bash
set -e
clang-6.0 -O2 -target bpf -c patmatch.c -o patmatch.o
echo "build complete"
hexout=$(/home/tkeeling/ubpf/vm/test patmatch.o --mem /home/tkeeling/ubpf/vm/data64)
printf "Return Value: $hexout (%d)\n" $((16#${hexout:2}))
