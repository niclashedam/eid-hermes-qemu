# eBPF to native machine code coverter

When an eBPF program is loaded into the linux kernel, it is JIT compiled
and waits to be attached to a probe.

The linux source includes a bpftool (linux/tools/bpf/bpftool/) which may be
used to get information on loaded BPF programs and dump their jited content.

This project includes two example eBPF programs, simple.c and patmatch.c.

Also included is `load_bpf`. This program will convert an eBPF binary into
bpf_instructions and attempt to load this BPF. Note that it currently does not
attach the program to anything, though it still must pass the verifier. The
BPF program will be loaded for as long as the program is running.

The binary must be only the executable portion of the ELF (by default .test).
This extraction is done for when you run `./jit_bpf.sh`, though you may do it
manually with `./extract_elf.sh infile.o extracted.o .text`

## Usage
1. Download linux source
1. Apply the `bpftool.patch`.
2. Make bpftool: `cd linux/tools/bpf/bpftool && make`
3. In this directory, `Make all` to compile the eBPF programs and load_bpf.
4. Select the ELF you would like to JIT
5. Run `sudo ./jit_bpf.sh infile.o [outfile_jited]`. This script will extract
the .text section of your infile, launch a load_bpf process in the
background, run bpftool to dump the JIT, and then close the background process.
    * This script needs to know the path of bpftool. You can:
      * Copy bpftool to this directory
      * Provide the path directly
        (`sudo BPF_TOOL=/path/to/bpftool ./jit_bpf.sh infile.o`)
      * Add this variable to your env (run with sudo -E if necessary)

**BAM!** You now have a binary for this machine.

For eBPF -> riscv compilation:
* Spin up a riscv linux vm (requires at least busybox?) (Yocto?)
* Cross compile load_bpf.c for riscv and copy it onto there.
* Cross compile your eBPF programs [for eBPF] and copy int onto there.
* Run the usage instructions again?
