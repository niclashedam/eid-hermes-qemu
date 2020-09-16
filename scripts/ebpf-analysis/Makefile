test_jit: test_jit.c
	gcc test_jit.c -o out -Wall
	# gcc test_jit.c external/bpf_jit_core.c external/core.c external/bpf_jit_comp32.c \
	# -o out -Iexternal #-I/home/tkeeling/linux/tools/include/uapi -I/home/tkeeling/linux/include

all : patmatch_eBPF patmatch_linux

patmatch_eBPF: patmatch.c
	clang-6.0 -O2 -target bpf -c patmatch.c -o patmatch_eBPF.o

patmatch_linux: patmatch.c
	gcc -o patmatch_linux.o patmatch.c -D DEBUG

.PHONY : clean
clean :
	-rm *\.o
