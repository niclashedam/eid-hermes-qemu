#include "ebpf.h"

/* uBPF will call the first function in a file (this one)
 *
 * input: "If --mem is given then the specified file will be read
 * and a pointer to its data passed in r1."
 *
 * eBPF registers are 64 bits (however one may access arbitrary length data ???)
 */
int num_occurances(int *c)
{
    char source[] = "This is a regex test strig. tents r cool.te";
    char pattern[] = "te";

    int num_occ = 0;
    for (int i = 0; i < ARRAY_SIZE(source) - ARRAY_SIZE(pattern); i++) {
        for (int j = 0; j < ARRAY_SIZE(pattern)-1; j++) {
            // return ARRAY_SIZE(pattern);
            if (source[i+j] != pattern[j])
                break;
            // if (j == ARRAY_SIZE(pattern) - 2)
            //     return i+j;
            // if (i == 2 && j == 1) {
            //     return source[0];
        }
    }

    return num_occ;
}

int main(int argc, char *argv[])
{
    int res = num_occurances(0);
    PRINT("Printing Result: %d\n", res);
    return res;
}

