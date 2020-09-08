all : patmatch_eBPF patmatch_linux

patmatch_eBPF: patmatch.c
	clang-6.0 -O2 -target bpf -c patmatch.c -o patmatch_eBPF.o

patmatch_linux: patmatch.c
	gcc -o patmatch_linux.o patmatch.c -D DEBUG



