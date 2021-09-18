#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"

#undef __SIZEOF_INT128__

#include "math128.h"

int main (int argc, char **argv)
{
    int i = 0;
    __uint128_t a, b;

    for (a = 0;;) {

// printf ("prog %016llx %016llx\n", (unsigned long long) (a >> 64), (unsigned long long) (a & 0xffffffffffffffffULL));

        for (b = 0; b < ((__uint128_t ) 1ULL << 32); b = (b + 1) * 68 / 67) {
            struct struct128bit c;

            __uint128_t r;
            i++;
            c.lo = a & 0xffffffffffffffffUL;
            c.hi = a >> 64;
            widemul32 (&c, (uint64_t) b);
            r = a * b;
            if (a && r / a != b)
                continue;
            if (b && r / b != a)
                continue;
            if ((__uint128_t) c.lo != (r & 0xffffffffffffffffULL)) {
                printf ("er1 %llx * %016llx %016llx\n", (unsigned long long) b, (unsigned long long) (a >> 64), (unsigned long long) (a & 0xffffffffffffffffULL));
                printf ("= %016llx %016llx\n", (unsigned long long) (r >> 64), (unsigned long long) (r & 0xffffffffffffffffULL));
                printf ("= %016llx %016llx\n", (unsigned long long) (c.hi), (unsigned long long) (c.lo));
                fflush (stdout);
                exit (1);
            }
            if ((__uint128_t) c.hi != (r >> 64)) {
                printf ("er2\n");
                fflush (stdout);
                exit (1);
            }
//             printf ("%llu * %llu = \n", (unsigned long long) a, (unsigned long long) b);
        }

        __uint128_t overflow;
        overflow = a;

        a = (a + 1) * 258 / 257;

        if (overflow > a)
            break;
    }

    for (a = 0; a < ((__uint128_t ) 1ULL << 63); a = (a + 1) * 68 / 67) {
        for (b = 0; b < ((__uint128_t ) 1ULL << 63); b = (b + 1) * 130 / 120) {
            struct struct128bit c;
            __uint128_t r;
            i++;
            c.lo = c.hi = 0;
            widemul (&c, (uint64_t) a, (uint64_t) b);
            r = a * b;
            if ((__uint128_t) c.lo != (r & 0xffffffffffffffffULL)) {
                printf ("er1\n");
                fflush (stdout);
                exit (1);
            }
            if ((__uint128_t) c.hi != (r >> 64)) {
                printf ("er2\n");
                fflush (stdout);
                exit (1);
            }
//             printf ("%llu * %llu = \n", (unsigned long long) a, (unsigned long long) b);
        }
    }
    fflush (stdout);
    printf ("success, %d multiplications done\n", i);
    fflush (stdout);
    return 0;
}





