# Integrating LiberaCrypt

## Include the public API

The installed target exposes the public include directory. Installed headers are namespaced below `LiberaCrypt/`, so applications normally include the umbrella header as:

```c
#include <LiberaCrypt/LiberaCrypt.h>
```

Public C functions, macros, constants, and algorithm selectors use the `LIBERAC_` prefix. Public type names use the `LiberaC` prefix.

## Runtime-selected algorithms

LiberaCrypt compiles supported parameter sets into one library. APIs that support runtime dispatch accept a `LiberaCAlgID` selector rather than requiring parameter-specific builds.

For example, a block-cipher operation selects the concrete AES mode through the final algorithm argument:

```c
LiberaCError error = LIBERAC_BLOCK_CIPHER_ENCRYPT(
    ciphertext, sizeof(ciphertext),
    plaintext, sizeof(plaintext),
    key, sizeof(key),
    initial_counter, sizeof(initial_counter),
    LIBERAC_ALG_AES_256_CTR);
```

The complete selector set is declared in `inc/Def.h` in the source tree and is installed as `<LiberaCrypt/Def.h>`. It is also available through `<LiberaCrypt/LiberaCrypt.h>`.

See [API overview](../api/overview.md) and [Algorithm selection](../api/algorithm-selection.md) for the dispatcher model and family boundaries.

## Public versus private implementation

Only headers in `inc/` form the supported source-tree public API; installation places those headers under `include/LiberaCrypt/`. Private declarations stay alongside their implementations under `src/`. Applications should not include internal headers or link against internal symbols.

Shared-library exports are restricted to the documented public API. Platform-specific export mechanisms are handled by the build system rather than exposed to consumers.

## Cryptographic responsibility

The library validates API-level sizes, identifiers, and many algorithm-specific parameter constraints, but it cannot choose a protocol for the application. Callers remain responsible for key management, nonce uniqueness, password policy, protocol-level algorithm restrictions, and deciding whether a legacy primitive is acceptable for an interoperability requirement.

Read [Security considerations](../security/security-considerations.md) before integrating low-level primitives directly.
