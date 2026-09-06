# LiberaCrypt

**Free cryptography, everywhere.**

LiberaCrypt is a **portability-first C11 cryptography library** providing classical and post-quantum cryptographic primitives through a consistent runtime-selected API.

> **Portable by construction.** Portability is treated as a correctness property, not merely as a list of platforms on which the code happens to build.

The implementation avoids depending on hidden assumptions about native integer representation, plain-`char` signedness, byte order, signed shifts, compiler extensions, ABI conventions, or a platform cryptographic runtime. OS-specific behavior is kept at narrow boundaries such as entropy acquisition and shared-library export policy.

## Why LiberaCrypt

- **Portability first** — ISO C11, fixed-width arithmetic, explicit byte-order handling, range reasoning, and defined integer behavior.
- **Broad platform compatibility** — implementation choices account for different compilers, architectures, ABIs, and legacy/non-mainstream Unix environments rather than only mainstream hosts.
- **Consistent runtime-selected API** — supported parameter sets are compiled into one library and selected with `LiberaCAlgID` where appropriate.
- **Operation-oriented interfaces** — raw block/stream encryption, authenticated encryption, hashing, MACs, KDFs, signatures, KEMs, and other families keep their own relevant parameters instead of sharing one oversized interface.
- **Measured implementation work** — optimization notes retain baselines, constraints, benchmark methodology, rejected experiments, and final implementation decisions.
- **Free software** — original LiberaCrypt source is released under `AGPL-3.0-only`; separately identified bundled components retain their upstream licenses.

## Cryptographic primitives

| Family | Implementations |
| --- | --- |
| Block ciphers | AES-128/192/256, three-key Triple-DES EDE |
| Stream cipher | ChaCha20 |
| Authenticated encryption | AES-GCM, AES-CCM, ChaCha20-Poly1305 |
| Hash / XOF | SHA-1, SHA-2, SHA-3, SHAKE, LSH |
| Message authentication | HMAC, CMAC, GMAC, Poly1305 |
| Key derivation | HKDF, PBKDF2-HMAC |
| Random generation | OS random bytes, CTR_DRBG |
| Public-key encryption | RSAES-OAEP, raw RSA primitive, ElGamal |
| Key agreement | ECDH (P-256/P-384/P-521), X25519 |
| Digital signatures | RSASSA-PSS, ECDSA, Ed25519, ML-DSA, SLH-DSA, AIMer, HAETAE |
| Key encapsulation | ML-KEM, NTRU+, SMAUG-T |

SHA-1, Triple-DES/TDEA, ECB, and raw RSA are retained for compatibility or primitive-level testing rather than as defaults for new protocol designs. See [Legacy and compatibility algorithms](docs/security/legacy-algorithms.md).

## Quick start

No submodule checkout or external cryptographic package is required for the normal build.

```sh
cmake -E make_directory build
cmake -E chdir build cmake .. \
  -DBUILD_SHARED_LIBS=ON \
  -DLIBERAC_BUILD_TESTS=ON \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
cmake -E chdir build ctest -C Release --output-on-failure
```

For a static library, configure with `-DBUILD_SHARED_LIBS=OFF`.

Installed CMake consumers can use the exported target:

```cmake
find_package(LiberaCrypt CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE LiberaCrypt::LiberaCrypt)
```

Installed public headers live below the `LiberaCrypt/` namespace. The umbrella header exposes the complete public API:

```c
#include <LiberaCrypt/LiberaCrypt.h>
```

A runtime-selected hash call, for example, keeps the algorithm choice in the same API family:

```c
uint8_t digest[LIBERAC_SHA2_256_DIGEST_BYTES];

LiberaCError error = LIBERAC_HASH(
    digest, sizeof(digest),
    message, message_length,
    LIBERAC_ALG_HASH_SHA2_256);
```

Public functions, macros, constants, and algorithm selectors use the `LIBERAC_` prefix; public type names use `LiberaC`.

## Documentation

The top-level README is intentionally only the project landing page. Detailed usage, design rationale, security notes, benchmarks, and implementation records live under [`docs/`](docs/README.md).

| Topic | Documentation |
| --- | --- |
| Build and integration | [Building](docs/getting-started/building.md) · [Integration](docs/getting-started/integration.md) |
| API model | [API overview](docs/api/overview.md) · [Algorithm selection](docs/api/algorithm-selection.md) |
| Algorithms | [Algorithm families](docs/algorithms/overview.md) · [Key derivation](docs/key-derivation.md) |
| Design | [Architecture](docs/design/architecture.md) · [Portability](docs/design/portability.md) · [Constant-time policy](docs/design/constant-time.md) |
| Security | [Security considerations](docs/security/security-considerations.md) · [Legacy algorithms](docs/security/legacy-algorithms.md) |
| Optimization | [Optimization index](docs/optimization/README.md) · [Bignum](docs/optimization/Bignum.md) · [ECC](docs/optimization/ECC.md) · [RSA](docs/optimization/RSA.md) · [ML-KEM](docs/optimization/ML-KEM.md) · [Ed25519](docs/optimization/Ed25519.md) |
| Benchmarks | [Benchmark organization](docs/benchmarks/README.md) |
| Development | [Testing and validation](docs/development/testing.md) |

### Generated API reference

Function signatures, parameters, return values, public declarations, and API-level reference material are generated from the headers in `inc/` with Doxygen 1.12 or newer:

```sh
cmake -E make_directory build-docs
cmake -E chdir build-docs cmake .. -DLIBERAC_BUILD_DOCS=ON
cmake --build build-docs --target liberacrypt_docs
```

The generated entry page is `build-docs/docs/html/index.html`.

Markdown documentation explains design and intended usage; Doxygen remains the function-level API reference so the same information does not have to be maintained twice.

## Portability

LiberaCrypt deliberately prefers explicit, defined behavior over code that is shorter but depends on a common-platform assumption.

Examples include explicit endian conversions, avoiding dependence on plain-`char` signedness, replacing signed-shift assumptions with defined operations, proving widths for fixed-point intermediates, avoiding unnecessary native 128-bit requirements, and adapting shared-library exports to each platform's native linker model.

The full engineering policy and review checklist are documented in [Portability](docs/design/portability.md).

## Architecture

Only headers under `inc/` form the source-tree public interface; installation places them under `include/LiberaCrypt/`. Operation/category entry points dispatch into concrete implementations under `src/`, while shared bignum, ECC, endian, NTT, prime, and related utilities remain internal.

Platform-specific behavior is kept at explicit boundaries. Shared-library exports use a canonical public-symbol allowlist and the native export mechanism for the host platform.

See [Architecture](docs/design/architecture.md) for the layer boundaries and rationale.

## Optimization and benchmarks

Optimization records are kept out of the landing page. Component documents describe the baseline implementation, optimization goal, correctness/timing constraints, portability considerations, benchmark method, measured result, and final decision.

This includes negative results. For example, the retained ML-KEM reduction experiments explain why the portable default kept Barrett reduction after hybrid and full-Montgomery variants regressed on the measured hosted runners.

See the [optimization index](docs/optimization/README.md) and [benchmark organization](docs/benchmarks/README.md).

## Testing

The test suite covers public-header isolation, operation-level tests, known-answer tests, compatibility regressions, supported post-quantum parameter sets, and focused negative/boundary behavior. Development also uses cross-toolchain builds, warnings, sanitizers, and selected interoperability oracles where appropriate.

See [Testing and validation](docs/development/testing.md) for the maintained overview.

## Third-party components

Portable PQC backends are vendored below their algorithm directories so a checkout is directly buildable. Their upstream notices and license files are retained with the source.

See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for provenance, pinned revisions or verified package hashes, and applicable upstream terms.

## License

Copyright (C) 2026 Myungjun Kim.

Except for separately identified third-party components, LiberaCrypt's original source code is licensed under the GNU Affero General Public License, version 3 only (`AGPL-3.0-only`). See [`LICENSE`](LICENSE) for the complete terms.

Vendored third-party sources remain under their respective upstream licenses as described in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
