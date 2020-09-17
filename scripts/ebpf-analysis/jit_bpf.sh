#!/bin/bash
set -e
trap 'end' EXIT
function end {
    set +e
    kill $(jobs -p) 2>> /dev/null # Ensures sigterm so BPF
                                  # file descriptor closes properly
    rm $tmpfile 2>> /dev/null
}

if [[ $1 == "-h" ]] || [[ "$#" -eq 0 ]]; then
    echo "\
Converts eBPF programs to native machine codeusing built-in JIT compiler.
BPF_TOOL must be provided (make linux/tools/bpf/bpftool)

Usage: sudo ./jit_bpf.sh infile.o outfile.o
"
    exit
fi

if [ -z $2 ]; then
    outfile=${1}_dump
else
    outfile=$2
fi

tmpfile=tmp_$$

# extract only .text section of ELF
echo "Extracting .text section of ELF:"
./extract_elf.sh $1 $tmpfile .text

# load an eBPF program and then wait for interrupt.
echo "Load eBPF program:"
./load_bpf $tmpfile &

sleep 1

# get JIT output
if [ -z $BPF_TOOL ]; then
    echo
    echo "No bpftool provided."
    echo "Provide bpftool path for JIT instruction dump."
    echo "Exiting script."
    echo
    exit
else
    $BPF_TOOL prog dump jited name $tmpfile >> /dev/null
    mv dump $outfile
    echo "JITed code saved at $outfile"
fi