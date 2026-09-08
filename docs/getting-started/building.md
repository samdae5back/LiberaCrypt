# Building LiberaCrypt

LiberaCrypt is a C11 library built with CMake. No submodule checkout or external cryptographic runtime is required for the normal library build.

## Shared-library build

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

## Install

```sh
cmake -E chdir build cmake .. -DCMAKE_INSTALL_PREFIX=/your/prefix
cmake --build build --target install --config Release
```

Only public headers under `inc/` are installed.

## CMake package

Installed consumers can use the exported target:

```cmake
find_package(LiberaCrypt CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE LiberaCrypt::LiberaCrypt)
```

## Release archives

Standalone builds expose CPack targets backed by the same `install()` rules used by normal installation:

```sh
cmake --build build --config Release --target package
```

Binary packages are written below `build/packages/`. Windows builds produce a ZIP archive; Unix-like builds produce a `.tar.gz` archive. The package name records the LiberaCrypt version, target platform, and whether the build is shared or static. A SHA-256 checksum is generated alongside each binary archive.

Source release archives can be generated independently:

```sh
cmake --build build --target package_source
```

Source packaging emits both `.tar.gz` and `.zip` formats and excludes Git metadata and common in-tree build directories.

## Tests

Tests are enabled by default for a standalone checkout and disabled when LiberaCrypt is included through `add_subdirectory()`. An embedding project may enable them with `-DLIBERAC_BUILD_TESTS=ON`; the embedding project's top-level CMake configuration must call `enable_testing()` for root-level CTest discovery.

See [Testing and validation](../development/testing.md) for the scope of the validation suite.

## API reference

Install Doxygen 1.12 or newer and enable the optional documentation target:

```sh
cmake -E make_directory build-docs
cmake -E chdir build-docs cmake .. -DLIBERAC_BUILD_DOCS=ON
cmake --build build-docs --target liberacrypt_docs
```

The generated entry page is `build-docs/docs/html/index.html`. Only public headers under `inc/` are included in the generated reference.
