#!/bin/bash
set -e
make
echo "Make complete. Running..."
set +e
./patmatch_linux.o
hexout=$(/home/tkeeling/ubpf/vm/test patmatch_eBPF.o --mem /home/tkeeling/ubpf/vm/data64)
printf "Return Value: $hexout (%d)\n" $((16#${hexout:2}))
