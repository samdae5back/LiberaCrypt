# Changelog

All notable user-visible changes to LiberaCrypt are recorded here. LiberaCrypt
is still in the `0.x` series, so minor releases may contain source or ABI
changes that require consumer updates.

## 0.6.0 - Unreleased

First release candidate for the consolidated LiberaCrypt public API.

### Added

- Runtime-selected C APIs for classical and post-quantum cryptographic families.
- Public compile-time version macros and `LIBERAC_VERSION()` runtime version
  query.
- CMake package export as `LiberaCrypt::LiberaCrypt`.
- Security reporting policy and third-party provenance/license notices.
- Cross-platform CI for Linux, macOS, Windows, 32-bit Linux, and big-endian
  s390x smoke validation.

### Packaging

- Public headers install below `include/LiberaCrypt/`.
- Shared libraries carry release `VERSION` and pre-1.0 minor `SOVERSION`
  metadata.
- Package compatibility is limited to the same `0.x` minor series; CMake 3.10
  uses the stricter exact-version fallback because `SameMinorVersion` is not
  available there.

### Internal

- Bignum schoolbook/Karatsuba dispatch no longer depends on CMake symbol-renaming
  compile definitions, so manual and CMake builds see the same internal symbol
  graph.
- Removed the unused generic NTT helper; algorithm-specific NTT implementations
  remain with the primitives that use them.
