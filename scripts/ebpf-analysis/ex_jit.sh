#!/bin/bash
trap 'end' EXIT
function end {
    set +e
    kill $(jobs -p) # Ensures sigterm so BPF file descriptor closes properly
    rm $tmpfile
}

set -e

tmpfile=tmp_$$

# extract only .text section of ELF
./extract_elf.sh $1 $tmpfile .text

# load an eBPF program and then wait for interrupt.
./load_bpf $tmpfile &

sleep 5

# get JIT output
if [ -z $BPFTOOL ]; then
    echo
    echo "No bpftool provided."
    echo "Provide bpftool path for JIT instruction dump."
    echo "Exiting script."
    echo
    exit
else
    $BPFTOOL prog dump jited name $tmpfile
fi
