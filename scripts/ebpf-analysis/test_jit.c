#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

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

void get_next_insn(char buf[CHUNK], union bpf *line) {
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
}

int filesize(FILE *fp) {
    int filesize;

    fseek(fp, 0L, SEEK_END);
    filesize = ftell(fp);
    printf("filsize: %d\n", filesize);
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
    while (fread(buf, 1, sizeof buf, fp_in)) {
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
    char *buf;
    int buflen = 1024 * 1024;

    num_insn = load_insns("patmatch_eBPF.o", &insns);
    if (num_insn < 1) {
        fprintf(stderr, "Error loading instructions.\n");
        return -1;
    }
    // for (int j = 0; j < num_insn; j++) {
    //     printf("0x%016lx\n", insns[j].code);
    // }

    buf = (char*)malloc(buflen*sizeof(char));
    if (buf==NULL) {
        fprintf(stderr, "error allocating memory.\n");
        return -1;
    }

    bpf_attr_load = (union bpf_attr){
        .prog_type = BPF_PROG_TYPE_UNSPEC,
        .insn_cnt = num_insn,
        .insns = ptr_to_u64(insns),
        .license = 0,
        .log_level = 3,
        .log_size = buflen, //??
        .log_buf = ptr_to_u64(buf),
        .kern_version = 0,
        .prog_flags = 0,
        .prog_name = "Search",
        .prog_ifindex = 0
    };

    int bpf_p = bpf(BPF_PROG_LOAD, &bpf_attr_load, sizeof(bpf_attr_load));

    printf("Printing buffer:\n");
    for (int j = 0; j < buflen; j++) {
        printf("%c", buf[j]);
    }

    int buflen2 = 512;
    char *buf2 = (char*)malloc(buflen2*sizeof(char));

    // printf("Printing file descriptor:\n");
    // FILE* fp = fdopen(bpf_p, "r");
    // while (fread(buf, 1, sizeof buf2, fp)) {
    //     printf("%s", buf2);
    // }


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