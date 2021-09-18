
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


#include "aes.h"

#define BLOCK_SZ                16

struct U128 {
    uint64_t hi;
    uint64_t lo;
};

union blockseq {
    struct U128 cnt;
    unsigned char block[BLOCK_SZ];
} __attribute__ ((packed));

struct _randseries {
    struct aes_key_st aes;
    union blockseq b;
};


static void U128_add (struct U128 *a, uint64_t c)
{
    uint64_t t;
    t = a->lo;
    a->lo += c;
    if (a->lo < t)
        a->hi++;
}

static void _randseries_init (FILE * f, struct _randseries *s, int key_sz)
{
    unsigned char *key;
    key = (unsigned char *) alloca (key_sz);
    if (fread (s->b.block, BLOCK_SZ, 1, f) != 1 || fread (key, key_sz, 1, f) != 1) {
        fprintf (stderr, "error: /dev/urandom returned less bytes than expected\n");
        exit (1);
    }
    if (aes_set_encrypt_key (key, key_sz * 8, &s->aes)) {
        fprintf (stderr, "error: failure setting key\n");
        exit (1);
    }
    memset (key, '\0', key_sz);
}

static void _randseries_next (struct _randseries *s, unsigned char *block, uint64_t salt)
{
    void *t;
    t = (void *) &s->b.cnt; /* defeat annoying alignment warning */
    U128_add ((struct U128 *) t, salt + 1);
    aes_encrypt (s->b.block, block, &s->aes);
}

#define N_RAND                 50

struct randseries {
    struct _randseries r[N_RAND];
    int key_sz;
    int i;
};

struct randseries *randseries_new (int key_sz)
{
    struct randseries *s;
    int i;
    FILE *f;
    s = (struct randseries *) malloc (sizeof (*s));
    memset (s, '\0', sizeof (*s));
    s->key_sz = key_sz;
    f = fopen ("/dev/urandom", "r");
    if (!f) {
        perror ("/dev/urandom");
        exit (1);
    }
    for (i = 0; i < N_RAND; i++)
        _randseries_init (f, &s->r[i], BLOCK_SZ);
    fclose (f);
    return s;
}

#if defined(__x86_64) || defined(__x86_64__) || defined(__i386) || defined(__i386__) || defined(i386)
static uint64_t timer_bits (void)
{
    unsigned hi, lo;
    asm volatile ("rdtsc":"=a" (lo), "=d" (hi));
    return ((uint64_t) lo) | (((uint64_t) hi) << 32);
}
#else
#define timer_bits()    clock()
#endif

void randseries_next (struct randseries *s, unsigned char *block)
{
    uint64_t bits;
    bits = (uint64_t) timer_bits ();    /* => add some random salt */
    _randseries_next (&s->r[s->i], block, bits);
    s->i = (s->i + 1) % N_RAND;
}

void randseries_bytes (struct randseries *s, void *out, int l)
{
    int i, n;
    unsigned char *v;
    n = (l + BLOCK_SZ - 1) - (l + BLOCK_SZ - 1) % BLOCK_SZ;
    v = (unsigned char *) alloca (n);
    for (i = 0; i < n; i += BLOCK_SZ)
        randseries_next (s, v + i);
    memcpy (out, v, l);
}

