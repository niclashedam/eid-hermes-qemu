#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>

union bpf
{
  unsigned long code;
  struct bpf_insn insn;
};

#define CHUNK 8

int main(int argc, char* argv[])
{
    FILE *fp_in;
    FILE *fp_out;
    unsigned char buf[CHUNK];
    size_t nread;
    union bpf line;
    unsigned int i;
    unsigned int npos = 0;


    if (!(fp_in = fopen("patmatch_eBPF.o", "r"))) {
        printf("error opening file.\n");
        return -1;
    }

    fp_out = stdout;

    // Each fread loads one 64 bit operation. Endianness must be switched
    while ((nread = fread(buf, 1, sizeof buf, fp_in)) > 0) {
        // fprintf(fp_out, "%04x: ", npos);
        // npos += CHUNK;

        // for (i = 0; i < CHUNK; i++) {
        //     fprintf(fp_out, "%02x ", buf[i]);
        // }
        // fprintf(fp_out, "\n");

        // Endian switch using long
        line.code = 0;
        for (i = 0; i < CHUNK; i++) {
            line.code += (unsigned long)buf[i] << i*8;
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

        // printf("    0x%016lx\n", line.code);
        // printf("  code: 0x%02x\n", line.insn.code);
        // printf("  src: 0x%01x\n", line.insn.src_reg);
        // printf("  dst: 0x%01x\n", line.insn.dst_reg);
        // printf("  off: 0x%04x\n", line.insn.off);
        // printf("  Imm: 0x%08x\n", line.insn.imm);

    }

    fclose(fp_in);

    return 0;
}