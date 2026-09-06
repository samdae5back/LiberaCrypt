/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "bignum_internal.h"
#include "Util/Core/secure_zero.h"

#include <stdlib.h>
#include <string.h>

static size_t bignum_words_length(const uint32_t *words, size_t length) {
    while (length != 0u && words[length - 1u] == 0u)
        --length;
    return length;
}

static int bignum_schoolbook_words(uint32_t *out,
                                   const uint32_t *a, size_t a_length,
                                   const uint32_t *b, size_t b_length) {
    size_t i, j, out_length;

    if (!out || (!a && a_length != 0u) || (!b && b_length != 0u))
        return -1;
    if (a_length > SIZE_MAX - b_length)
        return -1;

    out_length = a_length + b_length;
    if (out_length != 0u)
        memset(out, 0, out_length * sizeof(uint32_t));

    for (i = 0u; i < a_length; ++i) {
        uint64_t carry = 0u;
        for (j = 0u; j < b_length; ++j) {
            size_t index = i + j;
            uint64_t current = (uint64_t)a[i] * b[j] + out[index] + carry;
            out[index] = (uint32_t)current;
            carry = current >> 32;
        }
        if (b_length != 0u)
            out[i + b_length] = (uint32_t)carry;
    }
    return 0;
}

static int bignum_add_halves(uint32_t *out, size_t out_length,
                             const uint32_t *low, size_t low_length,
                             const uint32_t *high, size_t high_length) {
    size_t length = low_length > high_length ? low_length : high_length;
    size_t i;
    uint64_t carry = 0u;

    if (!out || out_length < length + 1u)
        return -1;
    memset(out, 0, out_length * sizeof(uint32_t));

    for (i = 0u; i < length; ++i) {
        uint64_t left = i < low_length ? low[i] : 0u;
        uint64_t right = i < high_length ? high[i] : 0u;
        uint64_t sum = left + right + carry;
        out[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    out[length] = (uint32_t)carry;
    return 0;
}

static int bignum_subtract_words(uint32_t *value, size_t value_length,
                                 const uint32_t *subtrahend,
                                 size_t subtrahend_length) {
    size_t i;
    uint64_t borrow = 0u;

    if (!value || (!subtrahend && subtrahend_length != 0u) ||
        subtrahend_length > value_length)
        return -1;

    for (i = 0u; i < value_length; ++i) {
        uint64_t right = (i < subtrahend_length ? subtrahend[i] : 0u) +
                         borrow;
        uint64_t left = value[i];
        value[i] = (uint32_t)(left - right);
        borrow = left < right;
    }
    return borrow == 0u ? 0 : -1;
}

static int bignum_add_shifted(uint32_t *out, size_t out_length,
                              const uint32_t *value, size_t value_length,
                              size_t offset) {
    size_t i;
    uint64_t carry = 0u;

    if (!out || (!value && value_length != 0u) || offset > out_length ||
        value_length > out_length - offset)
        return -1;

    for (i = 0u; i < value_length; ++i) {
        uint64_t sum = (uint64_t)out[offset + i] + value[i] + carry;
        out[offset + i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    i = offset + value_length;
    while (carry != 0u && i < out_length) {
        uint64_t sum = (uint64_t)out[i] + carry;
        out[i] = (uint32_t)sum;
        carry = sum >> 32;
        ++i;
    }
    return carry == 0u ? 0 : -1;
}

/*
 * One portable Karatsuba split with the schoolbook implementation as leaves.
 * The crossover benchmark only established a stable win for equally sized
 * operands at 96 limbs (3072 significant bits) and above, so production
 * dispatch stays deliberately inside that measured domain instead of
 * extrapolating to highly unbalanced operands.
 */
static int bignum_mul_karatsuba_noalias(LiberaCBignum *out,
                                        const LiberaCBignum *a,
                                        const LiberaCBignum *b) {
    size_t n, low_length, high_length, sum_length;
    size_t z0_capacity, z2_capacity, z1_capacity, required;
    size_t z0_length, z2_length, z1_length, product_length;
    size_t workspace_words, workspace_bytes, old_length;
    uint32_t *workspace = NULL;
    uint32_t *z0, *z2, *sum_a, *sum_b, *z1;
    int rc = -1;

    if (!out || !a || !b || out == a || out == b ||
        a->LENGTH != b->LENGTH ||
        a->LENGTH < BIGNUM_KARATSUBA_THRESHOLD_LIMBS)
        return -1;

    n = a->LENGTH;
    if (n > (SIZE_MAX - 8u) / 4u || n > SIZE_MAX / 2u)
        return -1;

    low_length = n / 2u;
    high_length = n - low_length;
    sum_length = high_length + 1u;
    z0_capacity = 2u * low_length;
    z2_capacity = 2u * high_length;
    z1_capacity = 2u * sum_length;
    required = z0_capacity + z2_capacity + 2u * sum_length + z1_capacity;

    workspace_words = 4u * n + 8u;
    if (workspace_words < required ||
        workspace_words > SIZE_MAX / sizeof(uint32_t))
        return -1;
    workspace_bytes = workspace_words * sizeof(uint32_t);
    workspace = (uint32_t *)malloc(workspace_bytes);
    if (!workspace)
        return -1;

    /* Every used sub-buffer is fully initialized by the helpers below.  Do not
     * zero the whole freshly allocated workspace here: that duplicates their
     * initialization and materially shifts the crossover on some runners.
     * The complete workspace is still securely zeroized before free. */
    z0 = workspace;
    z2 = z0 + z0_capacity;
    sum_a = z2 + z2_capacity;
    sum_b = sum_a + sum_length;
    z1 = sum_b + sum_length;

    if (bignum_schoolbook_words(z0, a->LIMBS, low_length,
                                b->LIMBS, low_length) != 0 ||
        bignum_schoolbook_words(z2, a->LIMBS + low_length, high_length,
                                b->LIMBS + low_length, high_length) != 0 ||
        bignum_add_halves(sum_a, sum_length,
                          a->LIMBS, low_length,
                          a->LIMBS + low_length, high_length) != 0 ||
        bignum_add_halves(sum_b, sum_length,
                          b->LIMBS, low_length,
                          b->LIMBS + low_length, high_length) != 0 ||
        bignum_schoolbook_words(z1, sum_a, sum_length,
                                sum_b, sum_length) != 0)
        goto done;

    z0_length = bignum_words_length(z0, z0_capacity);
    z2_length = bignum_words_length(z2, z2_capacity);
    if (bignum_subtract_words(z1, z1_capacity, z0, z0_length) != 0 ||
        bignum_subtract_words(z1, z1_capacity, z2, z2_length) != 0)
        goto done;
    z1_length = bignum_words_length(z1, z1_capacity);

    product_length = 2u * n;
    old_length = out->LENGTH;
    if (bignum_reserve(out, product_length) != 0)
        goto done;
    memset(out->LIMBS, 0, product_length * sizeof(uint32_t));
    if (old_length > product_length) {
        crypto_zeroize(out->LIMBS + product_length,
                       (old_length - product_length) * sizeof(uint32_t));
    }

    if (bignum_add_shifted(out->LIMBS, product_length,
                           z0, z0_length, 0u) != 0 ||
        bignum_add_shifted(out->LIMBS, product_length,
                           z1, z1_length, low_length) != 0 ||
        bignum_add_shifted(out->LIMBS, product_length,
                           z2, z2_length, 2u * low_length) != 0)
        goto done;

    out->LENGTH = product_length;
    bignum_normalize(out);
    rc = 0;

done:
    crypto_zeroize(workspace, workspace_bytes);
    free(workspace);
    return rc;
}

static int bignum_mul_karatsuba(LiberaCBignum *out,
                                const LiberaCBignum *a,
                                const LiberaCBignum *b) {
    LiberaCBignum tmp;
    int rc;

    if (out != a && out != b) {
        rc = bignum_mul_karatsuba_noalias(out, a, b);
        if (rc == 0)
            return 0;
        return crypto_bignum_mul_schoolbook(out, a, b);
    }

    crypto_bignum_init(&tmp);
    rc = bignum_mul_karatsuba_noalias(&tmp, a, b);
    if (rc == 0) {
        crypto_bignum_free(out);
        *out = tmp;
        crypto_bignum_init(&tmp);
    }
    crypto_bignum_free(&tmp);

    if (rc == 0)
        return 0;
    return crypto_bignum_mul_schoolbook(out, a, b);
}

LiberaCError crypto_bignum_mul(LiberaCBignum *out,
                               const LiberaCBignum *a,
                               const LiberaCBignum *b) {
    if (!out || !a || !b)
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    if (a->LENGTH == b->LENGTH &&
        a->LENGTH >= BIGNUM_KARATSUBA_THRESHOLD_LIMBS)
        return bignum_mul_karatsuba(out, a, b);

    return crypto_bignum_mul_schoolbook(out, a, b);
}
