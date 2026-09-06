/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "bignum_internal.h"

/*
 * Keep generic reduction in bignum.c, but make the externally visible generic
 * multiply-then-reduce helper use the production multiplication dispatcher.
 * The source-level schoolbook function remains available as the measured
 * fallback without relying on build-system symbol rewriting.
 */
LiberaCError crypto_bignum_mod_mul(LiberaCBignum *out,
                                   const LiberaCBignum *a,
                                   const LiberaCBignum *b,
                                   const LiberaCBignum *modulus) {
    LiberaCBignum product;
    LiberaCError rc;

    if (!out || !a || !b || !modulus || modulus->LENGTH == 0u)
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    crypto_bignum_init(&product);
    rc = crypto_bignum_mul(&product, a, b);
    if (rc == LIBERAC_SUCCESS)
        rc = crypto_bignum_mod(out, &product, modulus);
    crypto_bignum_free(&product);
    return rc;
}
