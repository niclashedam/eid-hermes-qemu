#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#define CHUNK 8 // single eBPF instruction size in bytes

static volatile sig_atomic_t keep_running = 1;

static void sig_handler(int _)
{
    (void)_;
    keep_running = 0;
}

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
  __u64 code;
  struct bpf_insn insn;
} bpf_u;

void get_next_insn(unsigned char buf[CHUNK], bpf_u *line) {
        // Endian switch using long
        line->code = 0;
        for (int i = 0; i < 8; i++) {
            line->code += (__u64)(buf[i] & 0xff) << i*8;
        }
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
        fprintf(stderr, "Error opening file for read.\n");
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
        if (i >= num_insn) {
            fprintf(stderr, "Incorrect file format.\n"); // avoid segfault
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
    int verbose = 0;

    if (argc < 2) {
        printf("Usage: ./test_jit eBPF_extracted_text.o [--verbose]\n");
        return -1;
    } else if (argc == 3) {
        verbose = 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    num_insn = load_insns(argv[1], &insns);
    if (num_insn < 1) {
        fprintf(stderr, "Error loading instructions.\n");
        return -1;
    }

    buf = (unsigned char*)malloc(buflen*sizeof(char));
    if (buf==NULL) {
        fprintf(stderr, "Error allocating memory.\n");
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

    if (verbose) {
        printf("Printing BPF instructions:\n");
        for (int j = 0; j < num_insn; j++) {
            printf("0x%016llx\n", insns[j].code);
        }
        printf("\n");
    }

    /* don't overwrite end character. */
    strncpy(bpf_attr_load.prog_name, argv[1], BPF_OBJ_NAME_LEN-1);

    int bpf_p = bpf(BPF_PROG_LOAD, &bpf_attr_load, sizeof(bpf_attr_load));

    if (bpf_p < 0) {
        printf("BPF error %d: %s (%d)\n", bpf_p, strerror(errno), errno);
        if (errno == 1) {
            printf("Please try again with sudo permissions.\n");
        } else if (errno == 22) {
            printf("Have you extracted the program section?.\n");
        }
        return -1;
    }

    if (verbose) {
        printf("Printing buffer:\n");
        for (int j = 0; j < buflen; j++) {
            printf("%c", buf[j]);
        }
        printf("\n");
    }

    /* We want eBPF program loaded only while this program is running.
     * one MUST close the eBPF file descriptor else the BPF will
     * persist after this program has terminated.
     */
    printf("BPF program loaded!\n");
    while (keep_running)
        sleep(1000);

    printf("Closing file descriptor...\n");
    close(bpf_p);
    free(insns);
    free(buf);
    return EXIT_SUCCESS;
}
