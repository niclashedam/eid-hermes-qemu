#include "eBPF.h"

/* uBPF will call the first function in a file (this one)
 *
 * input: "If --mem is given then the specified file will be read
 * and a pointer to its data passed in r1."
 *
 * eBPF registers are 64 bits (however one may access arbitrary length data ???)
 */
int num_occurances(int *c)
{
    char source[] = "apple This is an apple test strig. apples are cool.apple";
    char pattern[] = "apple";

    int count = 0;
    for (int i = 0; i < ARRAY_SIZE(source) - ARRAY_SIZE(pattern) + 1; i++) {
        // PRINT("%c", source[i]);

        // for pattern to match we need each letter in series to match
        // except the null character at the end
        for (int j = 0; j < ARRAY_SIZE(pattern)-1; j++) {
            if (source[i+j] != pattern[j])
                break;

            if (j == ARRAY_SIZE(pattern)-2) {
                count++;
#if DEBUG
                PRINT("MATCH FOUND @ pos: %d\n", i);
                for (int k = 0; k < i+j+1; k++) {
                    PRINT("%c", source[k]);
                }
                PRINT("\n");
                for (int k = 0; k < i; k++) {
                    PRINT(" ");
                }
                PRINT("^\n");
#endif
            }
        }
    }

    return count;
}


/* For testing
 */
int main(int argc, char *argv[])
{
    int res = num_occurances(0);
    PRINT("Printing Result: %d\n", res);
    return res;
}
