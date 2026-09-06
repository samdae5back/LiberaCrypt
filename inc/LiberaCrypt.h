/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * @file LiberaCrypt.h
 * @brief Umbrella header for the complete public LiberaCrypt C API.
 *
 * Include this header to use every supported API family. Applications that
 * need a smaller declaration surface may instead include an individual public
 * header such as <LiberaCrypt/BlockCipher.h> or
 * <LiberaCrypt/HashFunction.h>.
 *
 * @mainpage LiberaCrypt C API
 *
 * The library exposes one operation-oriented API per cryptographic family.
 * Algorithms and parameter sets are selected at runtime with a LiberaCAlgID
 * passed as the final function argument. Public functions are prefixed with
 * @c LIBERAC_, and failures are reported using LiberaCError status codes.
 *
 * @section crypto_quick_start Quick start
 * @code{.c}
 * #include <LiberaCrypt/LiberaCrypt.h>
 *
 * uint8_t digest[LIBERAC_SHA2_256_DIGEST_BYTES];
 * LiberaCError error = LIBERAC_HASH(
 *     digest, sizeof(digest), message, message_length,
 *     LIBERAC_ALG_HASH_SHA2_256);
 * @endcode
 *
 * See each family header for buffer ownership, parameter-set sizes, and
 * algorithm-specific constraints. The library does not allocate byte-array
 * output buffers on behalf of the caller; managed bignum and asymmetric-key
 * objects allocate their internal storage as needed.
 */
#ifndef LIBERAC_H
#define LIBERAC_H

#include "Def.h"
#include "Version.h"
#include "BlockCipher.h"
#include "StreamCipher.h"
#include "AuthenticatedEncryption.h"
#include "HashFunction.h"
#include "MessageAuthentication.h"
#include "KeyDerivation.h"
#include "RandomNumberGeneration.h"
#include "Util.h"
#include "AsymmetricCipher.h"
#include "KeyAgreement.h"
#include "KeyEncapsulation.h"
#include "DigitalSignature.h"

#endif
