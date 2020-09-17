all : patmatch_eBPF patmatch_linux simple load_bpf

load_bpf: load_bpf.c
	gcc load_bpf.c -o load_bpf -Wall
	# gcc test_jit.c external/bpf_jit_core.c external/core.c external/bpf_jit_comp32.c \
	# -o out -Iexternal #-I/home/tkeeling/linux/tools/include/uapi -I/home/tkeeling/linux/include

simple: simple.c
	clang-6.0 -O2 -target bpf -Wall -c simple.c -o simple.o

patmatch_eBPF: patmatch.c
	clang-6.0 -O2 -target bpf -c patmatch.c -o patmatch_eBPF.o

patmatch_linux: patmatch.c
	gcc -o patmatch_linux.o patmatch.c -D DEBUG

.PHONY : clean
clean:
	rm -f *\.o load_bpf