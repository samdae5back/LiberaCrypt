/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/* Feature-test macros must be visible before any system header. Linux needs
 * the GNU feature set for getrandom() on older libc headers; other Unix-like
 * targets only use POSIX.1-2001 interfaces in this translation unit. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#elif !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif

#include "random_internal.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif

int random_os_bytes(uint8_t *out, size_t length) {
    if (!out && length) return -1;
    while (length) {
        ULONG chunk = length > 0xffffffffu ? 0xffffffffu : (ULONG)length;
        if (BCryptGenRandom(NULL, out, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return -1;
        out += chunk;
        length -= chunk;
    }
    return 0;
}

#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif

static int read_urandom(uint8_t *out, size_t length) {
    int fd;
    do { fd = open("/dev/urandom", O_RDONLY); } while (fd < 0 && errno == EINTR);
    if (fd < 0) return -1;
    while (length) {
        size_t ask = length;
        ssize_t got;
        if (ask > 0x7ffff000u) ask = 0x7ffff000u;
        got = read(fd, out, ask);
        if (got < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (got == 0) {
            close(fd);
            return -1;
        }
        out += (size_t)got;
        length -= (size_t)got;
    }
    close(fd);
    return 0;
}

int random_os_bytes(uint8_t *out, size_t length) {
    if (!out && length) return -1;
#if defined(__linux__)
    while (length) {
        size_t ask = length;
        ssize_t got;
        if (ask > 0x7ffff000u) ask = 0x7ffff000u;
        got = getrandom(out, ask, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOSYS) break;
            return -1;
        }
        if (got == 0) break;
        out += (size_t)got;
        length -= (size_t)got;
    }
    if (length == 0) return 0;
#endif
    return read_urandom(out, length);
}
#endif

LiberaCError crypto_random_bytes_internal(uint8_t *out, size_t length) {
    if (!out && length) return LIBERAC_ERROR_INVALID_ARGUMENT;
    return random_os_bytes(out, length) == 0 ? LIBERAC_SUCCESS : LIBERAC_ERROR_RANDOM_FAILED;
}
