/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "bignum_internal.h"
#include "RandomNumberGeneration/Noise/random_internal.h"
#include "Util/Core/secure_zero.h"

#include <stdlib.h>
#include <string.h>

void crypto_bignum_init(LiberaCBignum *VALUE) {
    if (!VALUE) return;
    VALUE->LIMBS = NULL;
    VALUE->LENGTH = 0;
    VALUE->CAPACITY = 0;
}

void crypto_bignum_free(LiberaCBignum *VALUE) {
    if (!VALUE) return;
    if (VALUE->LIMBS) {
        crypto_zeroize(VALUE->LIMBS, VALUE->CAPACITY * sizeof(uint32_t));
        free(VALUE->LIMBS);
    }
    crypto_bignum_init(VALUE);
}

int bignum_reserve(LiberaCBignum *a, size_t capacity) {
    uint32_t *p;
    size_t old;
    if (!a) return -1;
    if (capacity <= a->CAPACITY) return 0;
    if (capacity > (size_t)-1 / sizeof(uint32_t)) return -1;
    old = a->CAPACITY;
    p = (uint32_t *)calloc(capacity, sizeof(uint32_t));
    if (!p) return -1;
    if (old) {
        memcpy(p, a->LIMBS, old * sizeof(uint32_t));
        crypto_zeroize(a->LIMBS, old * sizeof(uint32_t));
        free(a->LIMBS);
    }
    a->LIMBS = p;
    a->CAPACITY = capacity;
    return 0;
}

void bignum_normalize(LiberaCBignum *a) {
    if (!a) return;
    while (a->LENGTH && a->LIMBS[a->LENGTH - 1] == 0) --a->LENGTH;
}

static void bignum_clear_stale_tail(LiberaCBignum *value,
                                    size_t old_length,
                                    size_t new_length) {
    if (value && value->LIMBS && old_length > new_length) {
        crypto_zeroize(value->LIMBS + new_length,
                       (old_length - new_length) * sizeof(uint32_t));
    }
}

int crypto_bignum_copy(LiberaCBignum *OUT, const LiberaCBignum *IN) {
    size_t old_length;
    if (!OUT || !IN) return -1;
    if (OUT == IN) return 0;
    old_length = OUT->LENGTH;
    if (bignum_reserve(OUT, IN->LENGTH) != 0) return -1;
    if (IN->LENGTH) memcpy(OUT->LIMBS, IN->LIMBS, IN->LENGTH * sizeof(uint32_t));
    bignum_clear_stale_tail(OUT, old_length, IN->LENGTH);
    OUT->LENGTH = IN->LENGTH;
    return 0;
}

int crypto_bignum_set_u64(LiberaCBignum *OUT, uint64_t VALUE) {
    size_t old_length, new_length;
    if (!OUT) return -1;
    old_length = OUT->LENGTH;
    if (VALUE == 0) {
        bignum_clear_stale_tail(OUT, old_length, 0u);
        OUT->LENGTH = 0;
        return 0;
    }
    new_length = VALUE >> 32 ? 2u : 1u;
    if (bignum_reserve(OUT, new_length) != 0) return -1;
    OUT->LIMBS[0] = (uint32_t)VALUE;
    if (new_length == 2u)
        OUT->LIMBS[1] = (uint32_t)(VALUE >> 32);
    bignum_clear_stale_tail(OUT, old_length, new_length);
    OUT->LENGTH = new_length;
    return 0;
}

LiberaCError crypto_bignum_from_bytes_le(LiberaCBignum *OUT,
                                         const uint8_t *BYTES,
                                         size_t LENGTH) {
    size_t limbs, i;
    if (!OUT || (!BYTES && LENGTH)) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (LENGTH > (size_t)-1 / 8u)
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    limbs = (LENGTH + 3u) / 4u;
    if (bignum_reserve(OUT, limbs) != 0)
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    if (OUT->CAPACITY)
        crypto_zeroize(OUT->LIMBS, OUT->CAPACITY * sizeof(uint32_t));
    for (i = 0; i < LENGTH; ++i) OUT->LIMBS[i / 4u] |= (uint32_t)BYTES[i] << (8u * (i % 4u));
    OUT->LENGTH = limbs;
    bignum_normalize(OUT);
    return LIBERAC_SUCCESS;
}

LiberaCError crypto_bignum_from_bytes_be(LiberaCBignum *OUT,
                                         const uint8_t *BYTES,
                                         size_t LENGTH) {
    size_t limbs, i;
    if (!OUT || (!BYTES && LENGTH)) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (LENGTH > (size_t)-1 / 8u)
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    limbs = (LENGTH + 3u) / 4u;
    if (bignum_reserve(OUT, limbs) != 0)
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    if (OUT->CAPACITY)
        crypto_zeroize(OUT->LIMBS, OUT->CAPACITY * sizeof(uint32_t));
    for (i = 0; i < LENGTH; ++i) {
        size_t ri = LENGTH - 1u - i;
        OUT->LIMBS[i / 4u] |= (uint32_t)BYTES[ri] << (8u * (i % 4u));
    }
    OUT->LENGTH = limbs;
    bignum_normalize(OUT);
    return LIBERAC_SUCCESS;
}

size_t crypto_bignum_bit_length(const LiberaCBignum *VALUE) {
    uint32_t top;
    size_t bits;
    if (!VALUE || VALUE->LENGTH == 0) return 0;
    top = VALUE->LIMBS[VALUE->LENGTH - 1];
    bits = 32u * (VALUE->LENGTH - 1u);
    while (top) { ++bits; top >>= 1; }
    return bits;
}

size_t crypto_bignum_byte_length(const LiberaCBignum *VALUE) {
    size_t bits = crypto_bignum_bit_length(VALUE);
    return (bits + 7u) / 8u;
}

LiberaCError crypto_bignum_to_bytes_le(const LiberaCBignum *IN, uint8_t *OUT,
                                       size_t OUT_LENGTH) {
    size_t need, i;
    if (!IN || (!OUT && OUT_LENGTH)) return LIBERAC_ERROR_INVALID_ARGUMENT;
    need = crypto_bignum_byte_length(IN);
    if (OUT_LENGTH < need) return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    if (OUT_LENGTH) memset(OUT, 0, OUT_LENGTH);
    for (i = 0; i < need; ++i) OUT[i] = (uint8_t)(IN->LIMBS[i / 4u] >> (8u * (i % 4u)));
    return LIBERAC_SUCCESS;
}

LiberaCError crypto_bignum_to_bytes_be(const LiberaCBignum *IN, uint8_t *OUT,
                                       size_t OUT_LENGTH) {
    size_t need, i;
    if (!IN || (!OUT && OUT_LENGTH)) return LIBERAC_ERROR_INVALID_ARGUMENT;
    need = crypto_bignum_byte_length(IN);
    if (OUT_LENGTH < need) return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    if (OUT_LENGTH) memset(OUT, 0, OUT_LENGTH);
    for (i = 0; i < need; ++i) OUT[OUT_LENGTH - 1u - i] = (uint8_t)(IN->LIMBS[i / 4u] >> (8u * (i % 4u)));
    return LIBERAC_SUCCESS;
}

int crypto_bignum_compare(const LiberaCBignum *A, const LiberaCBignum *B) {
    size_t i;
    if (!A || !B) return 0;
    if (A->LENGTH < B->LENGTH) return -1;
    if (A->LENGTH > B->LENGTH) return 1;
    for (i = A->LENGTH; i > 0; --i) {
        uint32_t x = A->LIMBS[i - 1], y = B->LIMBS[i - 1];
        if (x < y) return -1;
        if (x > y) return 1;
    }
    return 0;
}

int crypto_bignum_is_zero(const LiberaCBignum *VALUE) {
    return !VALUE || VALUE->LENGTH == 0;
}

int crypto_bignum_add(LiberaCBignum *OUT, const LiberaCBignum *A,
                      const LiberaCBignum *B) {
    size_t a_length, b_length, old_length, n, i;
    uint64_t carry = 0u;
    if (!OUT || !A || !B) return -1;

    a_length = A->LENGTH;
    b_length = B->LENGTH;
    old_length = OUT->LENGTH;
    n = a_length > b_length ? a_length : b_length;
    if (n == SIZE_MAX || bignum_reserve(OUT, n + 1u) != 0)
        return -1;

    /* Addition is naturally alias-safe by limb: both source limbs are read
     * before the destination limb at the same index is overwritten.  Reusing
     * OUT therefore avoids a temporary allocation even for OUT == A/B. */
    for (i = 0u; i < n; ++i) {
        uint64_t av = i < a_length ? A->LIMBS[i] : 0u;
        uint64_t bv = i < b_length ? B->LIMBS[i] : 0u;
        uint64_t sum = av + bv + carry;
        OUT->LIMBS[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    if (carry != 0u)
        OUT->LIMBS[n++] = (uint32_t)carry;
    else
        OUT->LIMBS[n] = 0u;
    bignum_clear_stale_tail(OUT, old_length, n);
    OUT->LENGTH = n;
    return 0;
}

int crypto_bignum_sub(LiberaCBignum *OUT, const LiberaCBignum *A,
                      const LiberaCBignum *B) {
    size_t a_length, b_length, old_length, i;
    uint64_t borrow = 0u;
    if (!OUT || !A || !B || crypto_bignum_compare(A, B) < 0) return -1;

    a_length = A->LENGTH;
    b_length = B->LENGTH;
    old_length = OUT->LENGTH;
    if (bignum_reserve(OUT, a_length) != 0)
        return -1;

    /* As with addition, same-index overwrite is safe after both input limbs
     * have been loaded, so subtraction can reuse OUT for aliased operands. */
    for (i = 0u; i < a_length; ++i) {
        uint64_t av = A->LIMBS[i];
        uint64_t bv = (i < b_length ? B->LIMBS[i] : 0u) + borrow;
        OUT->LIMBS[i] = (uint32_t)(av - bv);
        borrow = av < bv;
    }
    OUT->LENGTH = a_length;
    bignum_normalize(OUT);
    bignum_clear_stale_tail(OUT, old_length, OUT->LENGTH);
    return 0;
}

static int bignum_mul_noalias(LiberaCBignum *out,
                              const LiberaCBignum *a,
                              const LiberaCBignum *b) {
    size_t a_length, b_length, old_length, product_length, i, j;
    if (!out || !a || !b || out == a || out == b)
        return -1;

    a_length = a->LENGTH;
    b_length = b->LENGTH;
    old_length = out->LENGTH;
    if (a_length == 0u || b_length == 0u) {
        bignum_clear_stale_tail(out, old_length, 0u);
        out->LENGTH = 0u;
        return 0;
    }
    if (a_length > SIZE_MAX - b_length)
        return -1;
    product_length = a_length + b_length;
    if (bignum_reserve(out, product_length) != 0)
        return -1;
    memset(out->LIMBS, 0, product_length * sizeof(uint32_t));
    bignum_clear_stale_tail(out, old_length, product_length);

    for (i = 0u; i < a_length; ++i) {
        uint64_t carry = 0u;
        for (j = 0u; j < b_length; ++j) {
            size_t k = i + j;
            uint64_t current = (uint64_t)a->LIMBS[i] * b->LIMBS[j] +
                               out->LIMBS[k] + carry;
            out->LIMBS[k] = (uint32_t)current;
            carry = current >> 32;
        }
        /* No earlier row can reach limb i+b_length.  Store the final carry
         * directly instead of entering a carry-propagation while loop. */
        out->LIMBS[i + b_length] = (uint32_t)carry;
    }
    out->LENGTH = product_length;
    bignum_normalize(out);
    return 0;
}

int crypto_bignum_mul_schoolbook(LiberaCBignum *OUT,
                                 const LiberaCBignum *A,
                                 const LiberaCBignum *B) {
    LiberaCBignum tmp;
    int rc;
    if (!OUT || !A || !B) return -1;

    if (OUT != A && OUT != B)
        return bignum_mul_noalias(OUT, A, B);

    /* Multiplication reuses source limbs across several output columns, so an
     * aliased destination still needs a temporary. */
    crypto_bignum_init(&tmp);
    rc = bignum_mul_noalias(&tmp, A, B);
    if (rc == 0) {
        crypto_bignum_free(OUT);
        *OUT = tmp;
        crypto_bignum_init(&tmp);
    }
    crypto_bignum_free(&tmp);
    return rc;
}

int bignum_get_bit(const LiberaCBignum *a, size_t bit) {
    size_t limb = bit / 32u;
    if (!a || limb >= a->LENGTH) return 0;
    return (int)((a->LIMBS[limb] >> (bit % 32u)) & 1u);
}

int bignum_shift_left_one(LiberaCBignum *a) {
    size_t i;
    uint64_t carry = 0;
    if (!a) return -1;
    if (a->LENGTH == 0) return 0;
    if (bignum_reserve(a, a->LENGTH + 1u) != 0) return -1;
    for (i = 0; i < a->LENGTH; ++i) {
        uint64_t v = ((uint64_t)a->LIMBS[i] << 1) | carry;
        a->LIMBS[i] = (uint32_t)v;
        carry = v >> 32;
    }
    if (carry) a->LIMBS[a->LENGTH++] = (uint32_t)carry;
    return 0;
}

int bignum_add_u32(LiberaCBignum *a, uint32_t v) {
    size_t i = 0;
    uint64_t carry = v;
    if (!a) return -1;
    if (!carry) return 0;
    if (a->LENGTH == 0) {
        if (bignum_reserve(a, 1) != 0) return -1;
        a->LIMBS[0] = v;
        a->LENGTH = 1;
        return 0;
    }
    while (carry && i < a->LENGTH) {
        uint64_t s = (uint64_t)a->LIMBS[i] + carry;
        a->LIMBS[i] = (uint32_t)s;
        carry = s >> 32;
        ++i;
    }
    if (carry) {
        if (bignum_reserve(a, a->LENGTH + 1u) != 0) return -1;
        a->LIMBS[a->LENGTH++] = (uint32_t)carry;
    }
    return 0;
}

static unsigned bignum_clz32(uint32_t value) {
    unsigned count = 0u;
    while ((value & UINT32_C(0x80000000)) == 0u) {
        value <<= 1;
        ++count;
    }
    return count;
}

int crypto_bignum_mod(LiberaCBignum *OUT, const LiberaCBignum *A,
                      const LiberaCBignum *MODULUS) {
    LiberaCBignum remainder;
    uint32_t *storage = NULL, *vn, *un;
    size_t n, m, words, i, j;
    unsigned shift;
    int rc = -1;

    if (!OUT || !A || !MODULUS || MODULUS->LENGTH == 0u)
        return -1;
    if (crypto_bignum_compare(A, MODULUS) < 0)
        return crypto_bignum_copy(OUT, A);
    if (MODULUS->LENGTH == 1u) {
        uint32_t divisor = MODULUS->LIMBS[0];
        uint32_t rem = bignum_mod_u32(A, divisor);
        return crypto_bignum_set_u64(OUT, rem);
    }

    n = MODULUS->LENGTH;
    if (n > SIZE_MAX - 1u || A->LENGTH > SIZE_MAX - 1u - n)
        return -1;
    words = n + A->LENGTH + 1u;
    if (words > SIZE_MAX / sizeof(uint32_t))
        return -1;

    storage = (uint32_t *)calloc(words, sizeof(uint32_t));
    if (!storage)
        return -1;
    vn = storage;
    un = storage + n;
    shift = bignum_clz32(MODULUS->LIMBS[n - 1u]);

    if (shift == 0u) {
        memcpy(vn, MODULUS->LIMBS, n * sizeof(uint32_t));
        memcpy(un, A->LIMBS, A->LENGTH * sizeof(uint32_t));
    } else {
        uint32_t carry = 0u;
        for (i = 0u; i < n; ++i) {
            uint64_t z = ((uint64_t)MODULUS->LIMBS[i] << shift) | carry;
            vn[i] = (uint32_t)z;
            carry = (uint32_t)(z >> 32);
        }
        carry = 0u;
        for (i = 0u; i < A->LENGTH; ++i) {
            uint64_t z = ((uint64_t)A->LIMBS[i] << shift) | carry;
            un[i] = (uint32_t)z;
            carry = (uint32_t)(z >> 32);
        }
        un[A->LENGTH] = carry;
    }

    /* Knuth-style normalized base-2^32 long division, specialized to retain
     * only the remainder.  This replaces the old bit-at-a-time shift/compare/
     * subtract loop with one quotient estimate per input limb. */
    m = A->LENGTH - n;
    for (j = m + 1u; j > 0u; --j) {
        const uint64_t radix = UINT64_C(1) << 32;
        size_t offset = j - 1u;
        uint64_t numerator = ((uint64_t)un[offset + n] << 32) |
                             un[offset + n - 1u];
        uint64_t qhat = numerator / vn[n - 1u];
        uint64_t rhat = numerator % vn[n - 1u];
        uint64_t borrow = 0u;
        uint32_t high;
        int underflow;

        while (qhat >= radix ||
               qhat * vn[n - 2u] >
                   (rhat << 32) + un[offset + n - 2u]) {
            --qhat;
            rhat += vn[n - 1u];
            if (rhat >= radix)
                break;
        }

        for (i = 0u; i < n; ++i) {
            uint64_t product = qhat * vn[i] + borrow;
            uint32_t low = (uint32_t)product;
            uint32_t minuend = un[offset + i];
            borrow = product >> 32;
            un[offset + i] = (uint32_t)(minuend - low);
            if (minuend < low)
                ++borrow;
        }

        high = un[offset + n];
        underflow = (uint64_t)high < borrow;
        un[offset + n] = (uint32_t)((uint64_t)high - borrow);
        if (underflow) {
            uint64_t carry = 0u;
            for (i = 0u; i < n; ++i) {
                uint64_t sum = (uint64_t)un[offset + i] + vn[i] + carry;
                un[offset + i] = (uint32_t)sum;
                carry = sum >> 32;
            }
            un[offset + n] =
                (uint32_t)((uint64_t)un[offset + n] + carry);
        }
    }

    crypto_bignum_init(&remainder);
    if (bignum_reserve(&remainder, n) != 0)
        goto done;
    if (shift == 0u) {
        memcpy(remainder.LIMBS, un, n * sizeof(uint32_t));
    } else {
        uint32_t carry = 0u;
        for (i = n; i > 0u; --i) {
            uint32_t word = un[i - 1u];
            remainder.LIMBS[i - 1u] = (word >> shift) | carry;
            carry = word << (32u - shift);
        }
    }
    remainder.LENGTH = n;
    bignum_normalize(&remainder);
    crypto_bignum_free(OUT);
    *OUT = remainder;
    crypto_bignum_init(&remainder);
    rc = 0;

done:
    crypto_bignum_free(&remainder);
    crypto_zeroize(storage, words * sizeof(uint32_t));
    free(storage);
    return rc;
}

int bignum_mul_u32(LiberaCBignum *out, const LiberaCBignum *a, uint32_t v) {
    LiberaCBignum t;
    size_t i;
    uint64_t carry = 0;
    if (!out || !a) return -1;
    crypto_bignum_init(&t);
    if (v == 0 || a->LENGTH == 0) {
        crypto_bignum_free(out);
        *out = t;
        return 0;
    }
    if (bignum_reserve(&t, a->LENGTH + 1u) != 0) goto fail;
    for (i = 0; i < a->LENGTH; ++i) {
        uint64_t z = (uint64_t)a->LIMBS[i] * v + carry;
        t.LIMBS[i] = (uint32_t)z;
        carry = z >> 32;
    }
    t.LENGTH = a->LENGTH;
    if (carry) t.LIMBS[t.LENGTH++] = (uint32_t)carry;
    crypto_bignum_free(out);
    *out = t;
    return 0;
fail:
    crypto_bignum_free(&t);
    return -1;
}

uint32_t bignum_mod_u32(const LiberaCBignum *a, uint32_t v) {
    uint64_t r = 0;
    size_t i;
    if (!a || v == 0) return 0;
    for (i = a->LENGTH; i > 0; --i) r = ((r << 32) | a->LIMBS[i - 1u]) % v;
    return (uint32_t)r;
}

int bignum_div_u32(LiberaCBignum *out, const LiberaCBignum *a, uint32_t v, uint32_t *remainder) {
    LiberaCBignum t;
    uint64_t rem = 0;
    size_t i;
    if (!out || !a || v == 0) return -1;
    crypto_bignum_init(&t);
    if (bignum_reserve(&t, a->LENGTH) != 0) goto fail;
    for (i = a->LENGTH; i > 0; --i) {
        uint64_t cur = (rem << 32) | a->LIMBS[i - 1u];
        t.LIMBS[i - 1u] = (uint32_t)(cur / v);
        rem = cur % v;
    }
    t.LENGTH = a->LENGTH;
    bignum_normalize(&t);
    if (remainder) *remainder = (uint32_t)rem;
    crypto_bignum_free(out);
    *out = t;
    return 0;
fail:
    crypto_bignum_free(&t);
    return -1;
}

int bignum_sub_u32(LiberaCBignum *out, const LiberaCBignum *a, uint32_t v) {
    LiberaCBignum b;
    int rc;
    crypto_bignum_init(&b);
    if (crypto_bignum_set_u64(&b, v) != 0) return -1;
    rc = crypto_bignum_sub(out, a, &b);
    crypto_bignum_free(&b);
    return rc;
}

int bignum_add_u32_copy(LiberaCBignum *out, const LiberaCBignum *a, uint32_t v) {
    if (crypto_bignum_copy(out, a) != 0) return -1;
    return bignum_add_u32(out, v);
}

typedef struct {
    size_t n;
    uint32_t n0inv;
    LiberaCBignum mod;
    LiberaCBignum r2;
    uint32_t *work;
} MONT_CTX;

static uint32_t mont_n0inv(uint32_t n0) {
    uint32_t x = 1u;
    int i;
    for (i = 0; i < 5; ++i) x *= 2u - n0 * x;
    return (uint32_t)(0u - x);
}

static void mont_clear(MONT_CTX *ctx) {
    if (!ctx) return;
    if (ctx->work) {
        crypto_zeroize(ctx->work, (ctx->n + 2u) * sizeof(uint32_t));
        free(ctx->work);
        ctx->work = NULL;
    }
    crypto_bignum_free(&ctx->mod);
    crypto_bignum_free(&ctx->r2);
    ctx->n = 0;
    ctx->n0inv = 0;
}

static int mont_init(MONT_CTX *ctx, const LiberaCBignum *mod) {
    LiberaCBignum x, tmp;
    size_t i, rounds;
    if (!ctx || !mod || mod->LENGTH == 0 || !(mod->LIMBS[0] & 1u)) return -1;
    ctx->n = mod->LENGTH;
    ctx->n0inv = mont_n0inv(mod->LIMBS[0]);
    crypto_bignum_init(&ctx->mod);
    crypto_bignum_init(&ctx->r2);
    crypto_bignum_init(&x);
    crypto_bignum_init(&tmp);
    ctx->work = (uint32_t *)calloc(ctx->n + 2u, sizeof(uint32_t));
    if (!ctx->work) goto fail;
    if (crypto_bignum_copy(&ctx->mod, mod) != 0 || crypto_bignum_set_u64(&x, 1) != 0) goto fail;
    rounds = 64u * ctx->n;
    for (i = 0; i < rounds; ++i) {
        if (bignum_shift_left_one(&x) != 0) goto fail;
        if (crypto_bignum_compare(&x, mod) >= 0) {
            if (crypto_bignum_sub(&tmp, &x, mod) != 0) goto fail;
            crypto_bignum_free(&x);
            x = tmp;
            crypto_bignum_init(&tmp);
        }
    }
    ctx->r2 = x;
    crypto_bignum_init(&x);
    crypto_bignum_free(&tmp);
    return 0;
fail:
    crypto_bignum_free(&x);
    crypto_bignum_free(&tmp);
    mont_clear(ctx);
    return -1;
}

static int mont_mul(LiberaCBignum *out, const LiberaCBignum *a, const LiberaCBignum *b, const MONT_CTX *ctx) {
    uint32_t *t;
    size_t n, i, j;
    LiberaCBignum r, tmp;
    if (!out || !a || !b || !ctx || !ctx->work) return -1;
    n = ctx->n;
    t = ctx->work;
    memset(t, 0, (n + 2u) * sizeof(uint32_t));

    for (i = 0; i < n; ++i) {
        uint64_t carry = 0;
        uint32_t bi = i < b->LENGTH ? b->LIMBS[i] : 0;
        for (j = 0; j < n; ++j) {
            uint32_t aj = j < a->LENGTH ? a->LIMBS[j] : 0;
            uint64_t z = (uint64_t)aj * bi + t[j] + carry;
            t[j] = (uint32_t)z;
            carry = z >> 32;
        }
        {
            uint64_t z = (uint64_t)t[n] + carry;
            t[n] = (uint32_t)z;
            t[n + 1u] += (uint32_t)(z >> 32);
        }

        {
            uint32_t m = t[0] * ctx->n0inv;
            carry = 0;
            for (j = 0; j < n; ++j) {
                uint64_t z = (uint64_t)m * ctx->mod.LIMBS[j] + t[j] + carry;
                t[j] = (uint32_t)z;
                carry = z >> 32;
            }
            {
                uint64_t z = (uint64_t)t[n] + carry;
                t[n] = (uint32_t)z;
                t[n + 1u] += (uint32_t)(z >> 32);
            }
        }

        for (j = 0; j <= n; ++j) t[j] = t[j + 1u];
        t[n + 1u] = 0;
    }

    crypto_bignum_init(&r);
    crypto_bignum_init(&tmp);
    if (bignum_reserve(&r, n + 1u) != 0) goto fail;
    memcpy(r.LIMBS, t, (n + 1u) * sizeof(uint32_t));
    r.LENGTH = n + 1u;
    bignum_normalize(&r);
    if (crypto_bignum_compare(&r, &ctx->mod) >= 0) {
        if (crypto_bignum_sub(&tmp, &r, &ctx->mod) != 0) goto fail2;
        crypto_bignum_free(&r);
        r = tmp;
        crypto_bignum_init(&tmp);
    }
    crypto_bignum_free(out);
    *out = r;
    crypto_bignum_free(&tmp);
    return 0;
fail:
    crypto_bignum_free(&r);
    crypto_bignum_free(&tmp);
    return -1;
fail2:
    crypto_bignum_free(&r);
    crypto_bignum_free(&tmp);
    return -1;
}

int crypto_bignum_mod_exp(LiberaCBignum *OUT, const LiberaCBignum *BASE, const LiberaCBignum *EXPONENT, const LiberaCBignum *MODULUS) {
    MONT_CTX ctx;
    LiberaCBignum base, base_m, acc, one, tmp;
    size_t bits, i;
    int rc = -1;
    if (!OUT || !BASE || !EXPONENT || !MODULUS || MODULUS->LENGTH == 0) return -1;
    if (!(MODULUS->LIMBS[0] & 1u)) {
        LiberaCBignum result, b, prod;
        crypto_bignum_init(&result); crypto_bignum_init(&b); crypto_bignum_init(&prod);
        if (crypto_bignum_set_u64(&result, 1) != 0 || crypto_bignum_mod(&b, BASE, MODULUS) != 0) goto even_fail;
        bits = crypto_bignum_bit_length(EXPONENT);
        for (i = 0; i < bits; ++i) {
            if (bignum_get_bit(EXPONENT, i)) {
                if (crypto_bignum_mul(&prod, &result, &b) != 0 || crypto_bignum_mod(&result, &prod, MODULUS) != 0) goto even_fail;
                crypto_bignum_free(&prod); crypto_bignum_init(&prod);
            }
            if (i + 1u < bits) {
                if (crypto_bignum_mul(&prod, &b, &b) != 0 || crypto_bignum_mod(&b, &prod, MODULUS) != 0) goto even_fail;
                crypto_bignum_free(&prod); crypto_bignum_init(&prod);
            }
        }
        if (crypto_bignum_mod(&result, &result, MODULUS) != 0) goto even_fail;
        crypto_bignum_free(OUT); *OUT = result; crypto_bignum_init(&result); rc = 0;
even_fail:
        crypto_bignum_free(&result); crypto_bignum_free(&b); crypto_bignum_free(&prod);
        return rc;
    }

    memset(&ctx, 0, sizeof(ctx));
    crypto_bignum_init(&base); crypto_bignum_init(&base_m); crypto_bignum_init(&acc); crypto_bignum_init(&one); crypto_bignum_init(&tmp);
    if (mont_init(&ctx, MODULUS) != 0) goto done;
    if (crypto_bignum_mod(&base, BASE, MODULUS) != 0 || crypto_bignum_set_u64(&one, 1) != 0) goto done;
    if (mont_mul(&base_m, &base, &ctx.r2, &ctx) != 0) goto done;
    if (mont_mul(&acc, &one, &ctx.r2, &ctx) != 0) goto done;
    bits = crypto_bignum_bit_length(EXPONENT);
    for (i = bits; i > 0; --i) {
        if (mont_mul(&tmp, &acc, &acc, &ctx) != 0) goto done;
        crypto_bignum_free(&acc); acc = tmp; crypto_bignum_init(&tmp);
        if (bignum_get_bit(EXPONENT, i - 1u)) {
            if (mont_mul(&tmp, &acc, &base_m, &ctx) != 0) goto done;
            crypto_bignum_free(&acc); acc = tmp; crypto_bignum_init(&tmp);
        }
    }
    if (mont_mul(&tmp, &acc, &one, &ctx) != 0) goto done;
    crypto_bignum_free(OUT); *OUT = tmp; crypto_bignum_init(&tmp);
    rc = 0;
done:
    mont_clear(&ctx);
    crypto_bignum_free(&base); crypto_bignum_free(&base_m); crypto_bignum_free(&acc); crypto_bignum_free(&one); crypto_bignum_free(&tmp);
    return rc;
}

LiberaCError crypto_bignum_random_bits(LiberaCBignum *OUT, size_t BITS,
                                       int SET_TOP_BIT, int SET_ODD) {
    uint8_t *buf;
    size_t bytes;
    unsigned unused;
    LiberaCError err;
    if (!OUT || BITS == 0) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (BITS > (size_t)-1 - 7u) return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    bytes = (BITS + 7u) / 8u;
    buf = (uint8_t *)malloc(bytes);
    if (!buf) return LIBERAC_ERROR_ALLOCATION_FAILED;
    err = crypto_random_bytes_internal(buf, bytes);
    if (err != LIBERAC_SUCCESS) {
        crypto_zeroize(buf, bytes);
        free(buf);
        return err;
    }
    unused = (unsigned)(bytes * 8u - BITS);
    if (unused) buf[0] &= (uint8_t)(0xffu >> unused);
    if (SET_TOP_BIT) buf[0] |= (uint8_t)(1u << (7u - unused));
    if (SET_ODD) buf[bytes - 1u] |= 1u;
    err = crypto_bignum_from_bytes_be(OUT, buf, bytes);
    crypto_zeroize(buf, bytes);
    free(buf);
    return err;
}

LiberaCError crypto_bignum_random_range(
    LiberaCBignum *OUT, const LiberaCBignum *UPPER_EXCLUSIVE) {
    LiberaCBignum x;
    size_t bits;
    int tries;
    LiberaCError err;
    if (!OUT || !UPPER_EXCLUSIVE || UPPER_EXCLUSIVE->LENGTH == 0)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    bits = crypto_bignum_bit_length(UPPER_EXCLUSIVE);
    crypto_bignum_init(&x);
    for (tries = 0; tries < 128; ++tries) {
        err = crypto_bignum_random_bits(&x, bits, 0, 0);
        if (err != LIBERAC_SUCCESS) goto fail;
        if (crypto_bignum_compare(&x, UPPER_EXCLUSIVE) < 0) {
            crypto_bignum_free(OUT);
            *OUT = x;
            return LIBERAC_SUCCESS;
        }
        crypto_bignum_free(&x); crypto_bignum_init(&x);
    }
    err = LIBERAC_ERROR_INTERNAL;
fail:
    crypto_bignum_free(&x);
    return err;
}
