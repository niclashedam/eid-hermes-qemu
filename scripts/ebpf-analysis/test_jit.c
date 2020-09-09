#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include "riscv/net/bpf_jit.h"

#define CHUNK 8

union bpf
{
  unsigned long code;
  struct bpf_insn insn;
};

void get_next_insn(char buf[CHUNK], union bpf *line) {
        // printf("%d: ", npos);
        // npos += CHUNK;
        // for (i = 0; i < CHUNK; i++) {
        //     fprintf(fp_out, "%02x ", buf[i]);
        // }
        // fprintf(fp_out, "\n");

        // Endian switch using long
        line->code = 0;
        for (int i = 0; i < CHUNK; i++) {
            line->code += (unsigned long)buf[i] << i*8;
        }

        // Endian switch using struct
        // line.insn.code = buf[0];
        // line.insn.src_reg = buf[1] >> 4;  // upper 4 bits
        // line.insn.dst_reg = buf[1] & 0xf; // lower 4 bits
        // line.insn.off = buf[2]
        //              + (buf[3] << 8);
        // line.insn.imm = buf[4]
        //              + (buf[5] << 8)
        //              + (buf[6] << 16)
        //              + (buf[7] << 24);

        // printf("  0x%016lx\n", line.code);
        // printf("  code: 0x%02x\n", line.insn.code);
        // printf("  src: 0x%01x\n", line.insn.src_reg);
        // printf("  dst: 0x%01x\n", line.insn.dst_reg);
        // printf("  off: 0x%04x\n", line.insn.off);
        // printf("  Imm: 0x%08x\n", line.insn.imm);
}

int filesize(FILE *fp) {
    int filesize;

    fseek(fp, 0L, SEEK_END);
    filesize = ftell(fp);
    printf("filsize: %d\n", filesize);
    fseek(fp, 0L, SEEK_SET);
    return filesize;
}

int main(int argc, char* argv[])
{
    FILE *fp_in;
    FILE *fp_out;
    unsigned char buf[CHUNK];
    size_t nread;
    union bpf line;
    unsigned int i;
    unsigned int npos = 0;
    int num_insn;

    struct rv_jit_context ctx;

    bpf_jit_build_prologue(&ctx);

    if (!(fp_in = fopen("patmatch_eBPF.o", "r"))) {
        printf("error opening file.\n");
        return -1;
    }

    num_insn = filesize(fp_in)/8;

    /* Each fread loads one 64 bit operation. Endianness must be switched
     * so that the instruciton can be mapped to a bpf_insn */
    while ((nread = fread(buf, 1, sizeof buf, fp_in)) > 0) {
        get_next_insn(buf, &line);
        printf("  0x%016lx\n", line.code);
    }

    fclose(fp_in);

    return 0;
}