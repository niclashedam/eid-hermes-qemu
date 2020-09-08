#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>

union bpf
{
  unsigned long BPFcode;
  struct bpf_insn code;
};


#define CHUNK 16

FILE *hexdump_open(const char *path, const char *mode) {
    FILE *fp;
    if (!(fp = fopen(path, mode))) {
        printf("error opening '%s'", path);
        return 0;
    }
    return fp;
}

int main(int argc, char* argv[])
{
    union bpf test;
    test.code.code = 0x18;
    test.code.dst_reg = 0x3;
    test.code.src_reg = 0x5;
    test.code.imm = 0xf4a123c8;
    test.code.off = 0xfe09;
    printf("opcode: 0x%lx\n", test.BPFcode);

    FILE *fp_in;
    FILE *fp_out;
    unsigned char buf[CHUNK];
    size_t nread;
    int i, c, npos;


    /* open the input file */
    fp_in = hexdump_open("patmatch_eBPF.o", "r");

    /* redirect output if an output file is defined */
    fp_out = stdout;

    npos = 0;
    /* display hex data CHUNK bytes at a time */
    while ((nread = fread(buf, 1, sizeof buf, fp_in)) > 0) {
        fprintf(fp_out, "%04x: ", npos);
        npos += CHUNK;

        /* print hex values e.g. 3f 62 ec f0*/
        for (i = 0; i < CHUNK; i++) {
            fprintf(fp_out, "%02x", buf[i]);
            if (!((i+1) % 4)) fprintf(fp_out, " ");
        }

        /* print ascii values e.g. ..A6..ó.j...D*/
        for (i = 0; i < CHUNK; i++) {
            c = buf[i];
            fprintf(fp_out, "%c", (c >= 33 && c <= 255 ? c : '.'));
        }
        fprintf(fp_out, "\n");
    }

    fclose(fp_in);

    return 0;
}