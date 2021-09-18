/* Copyright (C) 2020  Paul Sheer, All rights reserved. */

/* This file is derived from the work of Rhys Weatherley <rhys.weatherley@gmail.com> */

/* Supports curve448 in pure C for 32-bit and 64-bit builds. */


/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>



#define field_a_restrict_t field_t *__restrict__

#define FIELD_BITS                      448

#include "math128.h"


struct field_s {
    uint64_t limb[8];
} __attribute__ ((aligned (32)));

typedef struct field_s field_t;


static void field_set_ui (field_t * out, uint64_t x);
static void field_add_RAW (field_t * out, const field_t * a, const field_t * b);
static void field_sub_RAW (field_t * out, const field_t * a, const field_t * b);
static void field_neg_RAW (field_t * out, const field_t * a);
static void field_bias (field_t * a, int amt);
static void field_weak_reduce (field_t * a);
static void field_mul (field_t * __restrict__ cs, const field_t * as, const field_t * bs);
static void field_mulw (field_t * __restrict__ cs, const field_t * as, uint64_t b);
static void field_sqr (field_t * __restrict__ cs, const field_t * as);
static void field_strong_reduce (field_t * a);
static void field_serialize (uint8_t * serial, const field_t * x);
static uint64_t field_deserialize (field_t * x, const uint8_t serial[56]);


typedef field_t field_a_t[1];


/**
 * Unaligned big (vector?) register.
 */
typedef struct {
    uint64_t unaligned;
} __attribute__ ((packed)) unaligned_br_t;

/**
 * Unaligned word register, for architectures where that matters.
 */
typedef struct {
    uint64_t unaligned;
} __attribute__ ((packed)) unaligned_word_t;

/**
 * Copy one field element to another.
 */
static inline void field_copy (field_a_restrict_t a, const field_a_restrict_t b)
{
    memcpy (a, b, sizeof (*a));
}

/**
 * Square x, n times.
 */
static inline void field_sqrn (field_a_restrict_t y, const field_a_t x, int n)
{
    field_a_t tmp;
    assert (n > 0);
    if (n & 1) {
        field_sqr (y, x);
        n--;
    } else {
        field_sqr (tmp, x);
        field_sqr (y, tmp);
        n -= 2;
    }
    for (; n; n -= 2) {
        field_sqr (tmp, y);
        field_sqr (y, tmp);
    }
}

/* Multiply by signed curve constant */
static inline void field_mulw_scc (field_a_restrict_t out, const field_a_t a, int64_t scc)
{
    if (scc >= 0) {
        field_mulw (out, a, scc);
    } else {
        field_mulw (out, a, -scc);
        field_neg_RAW (out, out);
        field_bias (out, 2);
    }
}

/* Multiply by signed curve constant and weak reduce if biased */
static inline void field_mulw_scc_wr (field_a_restrict_t out, const field_a_t a, int64_t scc)
{
    field_mulw_scc (out, a, scc);
    if (scc < 0)
        field_weak_reduce (out);
}

static inline void field_subx_RAW (field_a_t d, const field_a_t a, const field_a_t b)
{
    field_sub_RAW (d, a, b);
    field_bias (d, 2);
}

static inline void field_sub (field_a_t d, const field_a_t a, const field_a_t b)
{
    field_sub_RAW (d, a, b);
    field_bias (d, 2);
    field_weak_reduce (d);
}

static inline void field_add (field_a_t d, const field_a_t a, const field_a_t b)
{
    field_add_RAW (d, a, b);
    field_weak_reduce (d);
}

static inline void field_subw_RAW (field_a_t d, uint64_t c)
{
    field_subw_RAW (d, c);
    field_bias (d, 1);
    field_weak_reduce (d);
}

static inline void field_neg (field_a_t d, const field_a_t a)
{
    field_neg_RAW (d, a);
    field_bias (d, 2);
    field_weak_reduce (d);
}

static void field_set_ui (field_t * out, uint64_t x)
{
    int i;
    out->limb[0] = x;
    for (i = 1; i < 8; i++) {
        out->limb[i] = 0;
    }
}

static void field_add_RAW (field_t * out, const field_t * a, const field_t * b)
{
    unsigned int i;
    for (i = 0; i < sizeof (*out) / sizeof (uint64_t); i++) {
        ((uint64_t *) out)[i] = ((const uint64_t *) a)[i] + ((const uint64_t *) b)[i];
    }
}

static void field_sub_RAW (field_t * out, const field_t * a, const field_t * b)
{
    unsigned int i;
    for (i = 0; i < sizeof (*out) / sizeof (uint64_t); i++) {
        ((uint64_t *) out)[i] = ((const uint64_t *) a)[i] - ((const uint64_t *) b)[i];
    }
}

static void field_neg_RAW (field_t * out, const field_t * a)
{
    unsigned int i;
    for (i = 0; i < sizeof (*out) / sizeof (uint64_t); i++) {
        ((uint64_t *) out)[i] = -((const uint64_t *) a)[i];
    }
}

static void field_bias (field_t * a, int amt)
{
    uint64_t co1 = ((1ull << 56) - 1) * amt, co2 = co1 - amt;
    unsigned int i;
    for (i = 0; i < sizeof (*a) / sizeof (uint64_t); i++) {
        a->limb[i] += (i == 4) ? co2 : co1;
    }
}

static void field_weak_reduce (field_t * a)
{
    /* PERF: use pshufb/palignr if anyone cares about speed of this */
    uint64_t mask = (1ull << 56) - 1;
    uint64_t tmp = a->limb[7] >> 56;
    int i;
    a->limb[4] += tmp;
    for (i = 7; i > 0; i--) {
        a->limb[i] = (a->limb[i] & mask) + (a->limb[i - 1] >> 56);
    }
    a->limb[0] = (a->limb[0] & mask) + tmp;
}


static void field_mul (field_t * __restrict__ cs, const field_t * as, const field_t * bs)
{
    const uint64_t *a = as->limb, *b = bs->limb;
    uint64_t *c = cs->limb;

    uint128_t accum0 = U128_0, accum1 = U128_0, accum2;
    uint64_t mask = (1ull << 56) - 1;

    uint64_t aa[4], bb[4], bbb[4];

    unsigned int i;
    for (i = 0; i < 4; i++) {
        aa[i] = a[i] + a[i + 4];
        bb[i] = b[i] + b[i + 4];
        bbb[i] = bb[i] + b[i + 4];
    }

    for (i = 0; i < 4; i++) {
        u128zero (accum2);

        unsigned int j;
        for (j = 0; j <= i; j++) {
            u128muladd (accum2, a[j], b[i - j]);
            u128muladd (accum1, aa[j], bb[i - j]);
            u128muladd (accum0, a[j + 4], b[i - j + 4]);
        }
        for (; j < 4; j++) {
            u128muladd (accum2, a[j], b[i - j + 8]);
            u128muladd (accum1, aa[j], bbb[i - j + 4]);
            u128muladd (accum0, a[j + 4], bb[i - j + 4]);
        }

        u128sub (accum1, accum2);
        u128add (accum0, accum2);

        c[i] = u128lo (accum0) & mask;
        c[i + 4] = u128lo (accum1) & mask;

        u128shft (accum0, 56);
        u128shft (accum1, 56);
    }

    u128add (accum0, accum1);
    u128addi (accum0, c[4]);
    u128addi (accum1, c[0]);
    c[4] = u128lo (accum0) & mask;
    c[0] = u128lo (accum1) & mask;

    u128shft (accum0, 56);
    u128shft (accum1, 56);

    c[5] += u128lo (accum0);
    c[1] += u128lo (accum1);
}

static void field_mulw (field_t * __restrict__ cs, const field_t * as, uint64_t b)
{
    const uint64_t *a = as->limb;
    uint64_t *c = cs->limb;

    uint128_t accum0 = U128_0, accum4 = U128_0;
    uint64_t mask = (1ull << 56) - 1;

    int i;
    for (i = 0; i < 4; i++) {
        u128muladd (accum0, b, a[i]);
        u128muladd (accum4, b, a[i + 4]);
        c[i] = u128lo (accum0) & mask;
        u128shft (accum0, 56);
        c[i + 4] = u128lo (accum4) & mask;
        u128shft (accum4, 56);
    }

    u128add (accum0, accum4);
    u128addi (accum0, c[4]);
    c[4] = u128lo (accum0) & mask;
    c[5] += _u128shft (accum0, 56);

    u128addi (accum4, c[0]);
    c[0] = u128lo (accum4) & mask;
    c[1] += _u128shft (accum4, 56);
}

static void field_sqr (field_t * __restrict__ cs, const field_t * as)
{
    const uint64_t *a = as->limb;
    uint64_t *c = cs->limb;

    uint128_t accum0 = U128_0, accum1 = U128_0, accum2;
    uint64_t mask = (1ull << 56) - 1;

    uint64_t aa[4];

    /* For some reason clang doesn't vectorize this without prompting? */
    unsigned int i;
    for (i = 0; i < 4; i++) {
        aa[i] = a[i] + a[i + 4];
    }

    u128mul (accum2, a[0], a[3]);
    u128mul (accum0, aa[0], aa[3]);
    u128mul (accum1, a[4], a[7]);

    u128muladd (accum2, a[1], a[2]);
    u128muladd (accum0, aa[1], aa[2]);
    u128muladd (accum1, a[5], a[6]);

    u128sub (accum0, accum2);
    u128add (accum1, accum2);

    c[3] = u128lo (accum1) << 1 & mask;
    c[7] = u128lo (accum0) << 1 & mask;

    u128shft (accum0, 55);
    u128shft (accum1, 55);

    u128muladd (accum0, 2 * aa[1], aa[3]);
    u128muladd (accum1, 2 * a[5], a[7]);
    u128muladd (accum0, aa[2], aa[2]);
    u128add (accum1, accum0);

    u128mulsub (accum0, 2 * a[1], a[3]);
    u128muladd (accum1, a[6], a[6]);

    u128mul (accum2, a[0], a[0]);
    u128sub (accum1, accum2);
    u128add (accum0, accum2);

    u128mulsub (accum0, a[2], a[2]);
    u128muladd (accum1, aa[0], aa[0]);
    u128muladd (accum0, a[4], a[4]);

    c[0] = u128lo (accum0) & mask;
    c[4] = u128lo (accum1) & mask;

    u128shft (accum0, 56);
    u128shft (accum1, 56);

    u128mul (accum2, 2 * aa[2], aa[3]);
    u128mulsub (accum0, 2 * a[2], a[3]);
    u128muladd (accum1, 2 * a[6], a[7]);

    u128add (accum1, accum2);
    u128add (accum0, accum2);

    u128mul (accum2, 2 * a[0], a[1]);
    u128muladd (accum1, 2 * aa[0], aa[1]);
    u128muladd (accum0, 2 * a[4], a[5]);

    u128sub (accum1, accum2);
    u128add (accum0, accum2);

    c[1] = u128lo (accum0) & mask;
    c[5] = u128lo (accum1) & mask;

    u128shft (accum0, 56);
    u128shft (accum1, 56);

    u128mul (accum2, aa[3], aa[3]);
    u128mulsub (accum0, a[3], a[3]);
    u128muladd (accum1, a[7], a[7]);

    u128add (accum1, accum2);
    u128add (accum0, accum2);

    u128mul (accum2, 2 * a[0], a[2]);
    u128muladd (accum1, 2 * aa[0], aa[2]);
    u128muladd (accum0, 2 * a[4], a[6]);

    u128muladd (accum2, a[1], a[1]);
    u128muladd (accum1, aa[1], aa[1]);
    u128muladd (accum0, a[5], a[5]);

    u128sub (accum1, accum2);
    u128add (accum0, accum2);

    c[2] = u128lo (accum0) & mask;
    c[6] = u128lo (accum1) & mask;

    u128shft (accum0, 56);
    u128shft (accum1, 56);

    u128addi (accum0, c[3]);
    u128addi (accum1, c[7]);
    c[3] = u128lo (accum0) & mask;
    c[7] = u128lo (accum1) & mask;

    /* we could almost stop here, but it wouldn't be stable, so... */

    u128shft (accum0, 56);
    u128shft (accum1, 56);
    c[4] += u128lo (accum0) + u128lo (accum1);
    c[0] += u128lo (accum1);
}

static void field_strong_reduce (field_t * a)
{
    uint64_t mask = (1ull << 56) - 1;

    /* first, clear high */
    a->limb[4] += a->limb[7] >> 56;
    a->limb[0] += a->limb[7] >> 56;
    a->limb[7] &= mask;

    /* now the total is less than 2^448 - 2^(448-56) + 2^(448-56+8) < 2p */

    /* compute total_value - p.  No need to reduce mod p. */

    uint128_t scarry = U128_0;
    int i;
    for (i = 0; i < 8; i++) {
        u128addi (scarry, a->limb[i]);
        u128subi (scarry, ((i == 4) ? mask - 1 : mask));
        a->limb[i] = u128lo (scarry) & mask;
        s128shft (scarry, 56);
    }

    /* uncommon case: it was >= p, so now scarry = 0 and this = x
     * common case: it was < p, so now scarry = -1 and this = x - p + 2^448
     * so let's add back in p.  will carry back off the top for 2^448.
     */

    uint128_t scarry_plus1;
    scarry_plus1 = scarry;
    u128addi (scarry_plus1, 1);
    assert (u128loiszero (scarry) | u128loiszero (scarry_plus1));

    uint64_t scarry_mask = u128lo (scarry) & mask;
    uint128_t carry = U128_0;

    /* add it back */
    for (i = 0; i < 8; i++) {
        u128addi (carry, a->limb[i]);
        u128addi (carry, ((i == 4) ? (scarry_mask & ~1) : scarry_mask));
        a->limb[i] = u128lo (carry) & mask;
        u128shft (carry, 56);
    }

    u128add (carry, scarry);
    assert (u128loiszero (carry));
}

static void field_serialize (uint8_t * serial, const field_t * x)
{
    int i, j;
    field_t red;
    field_copy (&red, x);
    field_strong_reduce (&red);
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 7; j++) {
            serial[7 * i + j] = red.limb[i];
            red.limb[i] >>= 8;
        }
        assert (red.limb[i] == 0);
    }
}

static uint64_t field_deserialize (field_t * x, const uint8_t serial[56])
{
    int i, j;
    for (i = 0; i < 8; i++) {
        uint64_t out = 0;
        for (j = 0; j < 7; j++) {
            out |= ((uint64_t) serial[7 * i + j]) << (8 * j);
        }
        x->limb[i] = out;
    }

    /* Check for reduction.
     *
     * The idea is to create a variable ge which is all ones (rather, 56 ones)
     * if and only if the low $i$ words of $x$ are >= those of p.
     *
     * Remember p = little_endian(1111,1111,1111,1111,1110,1111,1111,1111)
     */
    uint64_t ge = -1, mask = (1ull << 56) - 1;
    for (i = 0; i < 4; i++) {
        ge &= x->limb[i];
    }

    /* At this point, ge = 1111 iff bottom are all 1111.  Now propagate if 1110, or set if 1111 */
    ge = (ge & (x->limb[4] + 1)) | is_zero (x->limb[4] ^ mask);

    /* Propagate the rest */
    for (i = 5; i < 8; i++) {
        ge &= x->limb[i];
    }

    return ~is_zero (ge ^ mask);
}



/**
 * \brief Conditional swap of two values in constant time.
 *
 * \param swap Set to 1 to swap the values or 0 to leave them as-is.
 * \param x The first value to swap.
 * \param y The second value to swap.
 *
 * Reference: http://tools.ietf.org/html/rfc7748
 */
static void cswap (unsigned char swap, field_t * x, field_t * y)
{
    uint64_t sel, dummy;
    unsigned char posn;
    sel = (uint64_t) (-((int64_t) swap));
    for (posn = 0; posn < (sizeof (x->limb) / sizeof (x->limb[0])); ++posn) {
        dummy = sel & (x->limb[posn] ^ y->limb[posn]);
        x->limb[posn] ^= dummy;
        y->limb[posn] ^= dummy;
    }
}

/**
 * \brief Evaluates the Curve448 function.
 *
 * \param mypublic Final output public key, 56 bytes.
 * \param secret Secret value; i.e. the private key, 56 bytes.
 * \param basepoint The input base point, 56 bytes.
 *
 * \return Returns 1 if the evaluation was successful, 0 if the inputs
 * were invalid in some way.
 *
 * Reference: http://tools.ietf.org/html/rfc7748
 */
int curve448 (unsigned char *mypublic, const unsigned char *secret, const unsigned char *basepoint)
{
    /* Implementation details from RFC 7748, section 5 */
    field_t x_1, x_2, z_2, x_3, z_3;
    field_t A, AA, B, BB, E, C, D, DA, CB;
    unsigned char swap = 0;
    unsigned char byte_val;
    unsigned char k_t;
    unsigned char bit = 7;
    unsigned char posn = 55;

    /* Initialize working variables */
    uint64_t success = field_deserialize (&x_1, basepoint);     /* x_1 = u */
    field_set_ui (&x_2, 1);     /* x_2 = 1 */
    field_set_ui (&z_2, 0);     /* z_2 = 0 */
    field_copy (&x_3, &x_1);    /* x_3 = u */
    field_set_ui (&z_3, 1);     /* z_3 = 1 */

    /* Loop on all bits of the secret from highest to lowest.
       We perform the required masking from RFC 7748 as we go */
    byte_val = secret[posn] | 0x80;
    for (;;) {
        /* Get the next bit of the secret and conditionally swap */
        k_t = (byte_val >> bit) & 1;
        swap ^= k_t;
        cswap (swap, &x_2, &x_3);
        cswap (swap, &z_2, &z_3);
        swap = k_t;

        /* Double and add for this bit */
        field_add (&A, &x_2, &z_2);     /* A = x_2 + z_2 */
        field_sqr (&AA, &A);    /* AA = A^2 */
        field_sub (&B, &x_2, &z_2);     /* B = x_2 - z_2 */
        field_sqr (&BB, &B);    /* BB = B^2 */
        field_sub (&E, &AA, &BB);       /* E = AA - BB */
        field_add (&C, &x_3, &z_3);     /* C = x_3 + z_3 */
        field_sub (&D, &x_3, &z_3);     /* D = x_3 - z_3 */
        field_mul (&DA, &D, &A);        /* DA = D * A */
        field_mul (&CB, &C, &B);        /* CB = C * B */
        field_add (&z_2, &DA, &CB);     /* x_3 = (DA + CB)^2 */
        field_sqr (&x_3, &z_2);
        field_sub (&z_2, &DA, &CB);     /* z_3 = x_1 * (DA - CB)^2 */
        field_sqr (&x_2, &z_2);
        field_mul (&z_3, &x_1, &x_2);
        field_mul (&x_2, &AA, &BB);     /* x_2 = AA * BB */
        field_mulw (&z_2, &E, 39081);   /* z_2 = E * (AA + a24 * E) */
        field_add (&A, &AA, &z_2);
        field_mul (&z_2, &E, &A);

        /* Move onto the next lower bit of the secret */
        if (bit) {
            --bit;
        } else if (posn > 1) {
            bit = 7;
            byte_val = secret[--posn];
        } else if (posn == 1) {
            bit = 7;
            byte_val = secret[--posn] & 0xFC;
        } else {
            break;
        }
    }

    /* Final conditional swap */
    cswap (swap, &x_2, &x_3);
    cswap (swap, &z_2, &z_3);

    /* Compute x_2 * z_2 ^ (p - 2)
       The value p - 2 is: FF...FEFF...FD, which from highest to lowest is
       223 one bits, followed by a zero bit, followed by 222 one bits,
       followed by another zero bit, and a final one bit.
       The naive implementation that squares for every bit and multiplies
       for every 1 bit requires 893 multiplications.  The following can
       do the same operation in 483 multiplications.  The basic idea is to
       create bit patterns and then "shift" them into position.  We start
       with a 4 bit pattern 1111, which we can square 4 times to get
       11110000 and then multiply by the 1111 pattern to get 11111111.
       We then repeat that to turn 11111111 into 1111111111111111, etc.
     */
    field_sqr (&B, &z_2);       /* Set A to a 4 bit pattern */
    field_mul (&A, &B, &z_2);
    field_sqr (&B, &A);
    field_mul (&A, &B, &z_2);
    field_sqr (&B, &A);
    field_mul (&A, &B, &z_2);
    field_sqr (&B, &A);         /* Set C to a 6 bit pattern */
    field_mul (&C, &B, &z_2);
    field_sqr (&B, &C);
    field_mul (&C, &B, &z_2);
    field_sqr (&B, &C);         /* Set A to a 8 bit pattern */
    field_mul (&A, &B, &z_2);
    field_sqr (&B, &A);
    field_mul (&A, &B, &z_2);
    field_sqr (&E, &A);         /* Set E to a 16 bit pattern */
    field_sqr (&B, &E);
    for (posn = 1; posn < 4; ++posn) {
        field_sqr (&E, &B);
        field_sqr (&B, &E);
    }
    field_mul (&E, &B, &A);
    field_sqr (&AA, &E);        /* Set AA to a 32 bit pattern */
    field_sqr (&B, &AA);
    for (posn = 1; posn < 8; ++posn) {
        field_sqr (&AA, &B);
        field_sqr (&B, &AA);
    }
    field_mul (&AA, &B, &E);
    field_sqr (&BB, &AA);       /* Set BB to a 64 bit pattern */
    field_sqr (&B, &BB);
    for (posn = 1; posn < 16; ++posn) {
        field_sqr (&BB, &B);
        field_sqr (&B, &BB);
    }
    field_mul (&BB, &B, &AA);
    field_sqr (&DA, &BB);       /* Set DA to a 128 bit pattern */
    field_sqr (&B, &DA);
    for (posn = 1; posn < 32; ++posn) {
        field_sqr (&DA, &B);
        field_sqr (&B, &DA);
    }
    field_mul (&DA, &B, &BB);
    field_sqr (&CB, &DA);       /* Set CB to a 192 bit pattern */
    field_sqr (&B, &CB);        /* 192 = 128 + 64 */
    for (posn = 1; posn < 32; ++posn) {
        field_sqr (&CB, &B);
        field_sqr (&B, &CB);
    }
    field_mul (&CB, &B, &BB);
    field_sqr (&DA, &CB);       /* Set DA to a 208 bit pattern */
    field_sqr (&B, &DA);        /* 208 = 128 + 64 + 16 */
    for (posn = 1; posn < 8; ++posn) {
        field_sqr (&DA, &B);
        field_sqr (&B, &DA);
    }
    field_mul (&DA, &B, &E);
    field_sqr (&CB, &DA);       /* Set CB to a 216 bit pattern */
    field_sqr (&B, &CB);        /* 216 = 128 + 64 + 16 + 8 */
    for (posn = 1; posn < 4; ++posn) {
        field_sqr (&CB, &B);
        field_sqr (&B, &CB);
    }
    field_mul (&CB, &B, &A);
    field_sqr (&DA, &CB);       /* Set DA to a 222 bit pattern */
    field_sqr (&B, &DA);        /* 222 = 128 + 64 + 16+ 8 + 6 */
    for (posn = 1; posn < 3; ++posn) {
        field_sqr (&DA, &B);
        field_sqr (&B, &DA);
    }
    field_mul (&DA, &B, &C);
    field_sqr (&CB, &DA);       /* Set CB to a 224 bit pattern */
    field_mul (&B, &CB, &z_2);  /* CB = DA|1|0 */
    field_sqr (&CB, &B);
    field_sqr (&BB, &CB);       /* Set BB to a 446 bit pattern */
    field_sqr (&B, &BB);        /* BB = DA|1|0|DA */
    for (posn = 1; posn < 111; ++posn) {
        field_sqr (&BB, &B);
        field_sqr (&B, &BB);
    }
    field_mul (&BB, &B, &DA);
    field_sqr (&B, &BB);        /* Set B to a 448 bit pattern */
    field_sqr (&BB, &B);        /* B = DA|1|0|DA|01 */
    field_mul (&B, &BB, &z_2);
    field_mul (&BB, &x_2, &B);  /* Set BB to x_2 * B */

    /* Serialize the result into the return buffer */
    field_serialize (mypublic, &BB);

    /* If the original base point was out of range, then fail now */
    return (int) (1 & success);
}

