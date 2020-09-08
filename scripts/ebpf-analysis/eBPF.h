#if defined(DEBUG)

    // #warning compiling for this computer (not eBPF)
    #include <stdio.h>
    #include <stdlib.h>
    #include <stddef.h>
    #define PRINT(f_, ...) printf((f_), ##__VA_ARGS__)

#else

    // #warning compiling for eBPF
    #define PRINT(f_, ...) do { } while (0)
    #endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
