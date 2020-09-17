#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>

#define CHUNK 8 // single eBPF instruction size (bytes)
#define DEBUG_LEN 15

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

typedef union bpf
{
  unsigned long code;
  struct bpf_insn insn;
} bpf_u;

void get_next_insn(unsigned char buf[CHUNK], bpf_u *line) {
        // Endian switch using long
        line->code = 0;
        for (int i = 0; i < 8; i++) {
            line->code += (unsigned long)(buf[i] & 0xff) << i*8;
        }

        // printf("next: 0x%016lx\n", line->code);

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
}

int filesize(FILE *fp) {
    int filesize;

    fseek(fp, 0L, SEEK_END);
    filesize = ftell(fp);
    printf("filesize: %d bytes\n", filesize);
    fseek(fp, 0L, SEEK_SET);
    return filesize;
}

/* This boy is meant to take compiled eBPF code and load it into the system.
 * returns: length of instructions
 */
int load_insns(char* filename, bpf_u **insns_p) {
    FILE *fp_in;
    unsigned char buf[CHUNK];
    int num_insn;
    int i = 0;
    bpf_u *insns; /* pointer to bpf_u array */

    if (!(fp_in = fopen(filename, "r"))) {
        fprintf(stderr, "error opening file.\n");
        return -1;
    }

    num_insn = filesize(fp_in)/8;
    insns = (bpf_u*)malloc(num_insn * sizeof(bpf_u));
    if (insns == NULL) {
        fprintf(stderr, "Error allocating memory.\n");
        return -1;
    }

    /* Each fread loads one 64 bit operation. Endianness must be switched
     * so that the instruciton can be mapped to a bpf_insn */
    while (fread(buf, 1, CHUNK, fp_in)) {
        if (!(i < num_insn)) {
            fprintf(stderr, "Allocation error, incorrect filesize\n");
            return -1;
        }
        get_next_insn(buf, &insns[i]);
        i++;
    }

    fclose(fp_in);
    *insns_p = insns;
    return num_insn;
}

int main(int argc, char* argv[])
{
    bpf_u *insns; /* array of len(num_insn) */
    int num_insn;
    union bpf_attr bpf_attr_load;
    unsigned char *buf;
    int buflen = 1024 * 1024;
    char *license = "GPL";

    num_insn = load_insns("pattxt.o", &insns);
    if (num_insn < 1) {
        fprintf(stderr, "Error loading instructions.\n");
        return -1;
    }

    for (int j = 0; j < num_insn; j++) {
        printf("insn %3d: 0x%016lx\n", j, insns[j].code);
    }

    // printf("line 8: 0x%016lx\n", (insns+8)->code); /* beginning for simple.o */

    buf = (unsigned char*)malloc(buflen*sizeof(char));
    if (buf==NULL) {
        fprintf(stderr, "error allocating memory.\n");
        return -1;
    }

    bpf_attr_load = (union bpf_attr){
        .prog_type = BPF_PROG_TYPE_PERF_EVENT,
        .insn_cnt = num_insn,
        .insns = ptr_to_u64(insns),
        .license = ptr_to_u64(license),
        .log_level = 1,
        .log_size = buflen,
        .log_buf = ptr_to_u64(buf),
        .kern_version = 5,
    };

    int bpf_p = bpf(BPF_PROG_LOAD, &bpf_attr_load, sizeof(bpf_attr_load));

    if (bpf_p < 0) {
        printf("bpf error %d: %s (%d)\n", bpf_p, strerror(errno), errno);
        return -1;
    }

    printf("Printing buffer:\n");
    for (int j = 0; j < buflen; j++) {
        printf("%c", buf[j]);
    }

    printf("\nBPF program loaded with fd %d. Press ^C to exit\n", bpf_p);
    while (1) sleep(100000);

    free(insns);
    free(buf);
    return 0;
}

// nonsense
        // printf("%d: ", npos);
        // npos += CHUNK;
        // for (i = 0; i < CHUNK; i++) {
        //     fprintf(fp_out, "%02x ", buf[i]);
        // }
        // fprintf(fp_out, "\n");

        // printf("  code: 0x%02x\n", line.insn.code);
        // printf("  src: 0x%01x\n", line.insn.src_reg);
        // printf("  dst: 0x%01x\n", line.insn.dst_reg);
        // printf("  off: 0x%04x\n", line.insn.off);
        // printf("  Imm: 0x%08x\n", line.insn.imm);