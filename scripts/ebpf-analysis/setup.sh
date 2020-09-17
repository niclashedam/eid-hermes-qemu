#!/bin/bash
trap 'kill $(jobs -p)' EXIT
set -e

# eBPF analysis

# Goal: Determine efficacy of C -> eBPF programs on RISCV for
# offloading purposes.

# The linux kernel has a built in JIT compiler which will be utilized in this process.

# 1. Cross compile C program for eBPF
echo -e "\n Cross compiling eBPF programs:"
make all

# 2. Extract only the eBPF instructions (.text section) from binary
echo -e "\nExtract eBPF instructions:"
./extract_elf.sh simple.o simple_text.o .text
./extract_elf.sh patmatch_eBPF.o patmatch_eBPF_text.o .text

# 3. compile load_bpf
make load_bpf

# 4.
echo "Setup complete"
echo "Run: sudo ./ex_jit.sh example_text.o"
make load_bpf
