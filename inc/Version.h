/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * @file Version.h
 * @brief Compile-time and runtime LiberaCrypt version information.
 *
 * The numeric macros describe the public release version of the headers.
 * LIBERAC_VERSION() returns the version of the linked library at runtime.
 *
 * @defgroup crypto_version Version API
 * @brief Header and linked-library version metadata.
 * @{
 */
#ifndef LIBERAC_VERSION_H
#define LIBERAC_VERSION_H

#include "Def.h"

/* Keep these values synchronized with project(LiberaCrypt VERSION ...) in the
 * top-level CMakeLists.txt. They are literal source definitions so consumers
 * building without CMake receive the same version metadata. */
#define LIBERAC_VERSION_MAJOR 0
#define LIBERAC_VERSION_MINOR 6
#define LIBERAC_VERSION_PATCH 0
#define LIBERAC_VERSION_STRING "0.6.0"

LIBERAC_BEGIN_DECLS

/**
 * @brief Return the version string of the linked LiberaCrypt library.
 * @return A process-lifetime string in `major.minor.patch` form.
 */
LIBERAC_API const char *LIBERAC_VERSION(void);

LIBERAC_END_DECLS

#endif

/** @} */
