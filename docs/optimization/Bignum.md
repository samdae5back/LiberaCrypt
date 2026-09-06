# Bignum optimization record

This document is the consolidated engineering record for LiberaCrypt's
second-stage arbitrary-precision arithmetic optimization.

## At a glance

| Stage | Baseline | Accepted change | Measured result |
|---|---|---|---|
| Stage 1 | bit-at-a-time generic reduction, repeated-doubling `R^2`, shifted CIOS | normalized base-2^32 remainder, direct `R^2`, integrated-shift CIOS | `mod` about **49x-83x**, `mod-mul` about **26x-55x** faster; CIOS itself **0.7%-17.1%** faster |
| Stage 2 | allocate/replace add/sub/mul/square, older schoolbook/square loops | safe output reuse, tighter schoolbook carry handling, single doubled-cross square accumulation | add/sub roughly **38%-66%**, square **15%-62%** faster; generic mul is a smaller/mixed **-2%-18%** change |
| Stage 3 | Stage-2 schoolbook multiplication | measured one-level portable Karatsuba dispatch for equal-width operands at **96 limbs / 3072 bits and above** | final production path at 3072 bits: **+6.0% Linux, +25.2% macOS, +12.5% Windows**; larger sizes show stronger gains |

All performance claims below are **same-run pairwise comparisons**. The
reference and candidate execute on the same hosted runner with the same
deterministic inputs. Absolute timings from different workflow runs are not
combined into a synthetic cumulative speedup.

The portable baseline remains 32-bit limbs with 32x32-to-64 arithmetic. These
stages require no `__uint128_t`, compiler intrinsics, assembly, or host-endian
word casts.

## Security boundary

The generic bignum layer is intentionally performance-oriented and variable-time.
Secret-sensitive protocol arithmetic remains on the fixed-width
constant-schedule path.

- Stage 1 shares the CIOS accumulation machinery, but the secret path keeps fixed
  loop counts and masked final reduction.
- Stage 2 changes the generic add/sub/mul/square paths; it does not replace the
  fixed-width secret exponentiation schedule.
- Stage 3 dispatches only the generic multiplication API. Fixed-width secret
  Montgomery arithmetic is not routed through Karatsuba.
- The Stage-3 Karatsuba workspace is securely zeroized before it is freed. A
  redundant initialization pass was removed only after verifying that every
  used sub-buffer is fully initialized by its arithmetic helper; the final
  zeroization remains.

---

# Stage 1 - public reduction and Montgomery core

## What changed

Before Stage 1, `crypto_bignum_mod()` scanned the dividend one bit at a time:
shift a temporary remainder, append one bit, compare, and conditionally
subtract. Stage 1 replaced this with:

1. normalized base-2^32 long-division remainder;
2. direct Montgomery `R^2` construction by reducing `2^(64n)` once;
3. integrated-shift CIOS Montgomery multiplication;
4. separate public and secret final-reduction policies retained.

The exact pre-Stage-1 formulations remain only as benchmark references.

## Benchmark result

### Generic remainder - speedup over original bitwise reducer

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 83.4x | 55.5x | 71.8x |
| 3072 | 69.5x | 48.6x | 60.0x |
| 4096 | 81.3x | 51.9x | 66.9x |

### Multiply then reduce - speedup over original path

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 55.3x | 32.3x | 44.2x |
| 3072 | 46.3x | 25.8x | 37.7x |
| 4096 | 52.8x | 30.3x | 42.6x |

### Montgomery `R^2` setup - speedup over repeated doubling

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 78.0x | 47.0x | 62.8x |
| 3072 | 67.4x | 41.7x | 57.1x |
| 4096 | 78.0x | 49.2x | 60.7x |

### Raw CIOS core - percent faster after integrated shift

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 4.1% | 3.4% | 8.1% |
| 3072 | 0.7% | 9.9% | 17.1% |
| 4096 | 4.5% | 11.9% | 15.0% |

The dominant Stage-1 improvement is the algorithmic reduction/setup change,
not the smaller CIOS loop optimization.

## Validation record

- final accurate benchmark run: `33740787602`
- validated head: `3c929f18ff207f9d7aa7357e8380632d856cbe62`
- artifacts:
  - `bignum-stage1-accurate-Linux`
  - `bignum-stage1-accurate-macOS`
  - `bignum-stage1-accurate-Windows`

The same Stage-1 head passed the complete CI matrix, RSA validation, ECC
validation, Bignum Validation, and sanitizer checks before merge.

---

# Stage 2 - output reuse and multiply/square inner loops

## What changed

Stage 2 targets allocator and inner-loop overhead left after Stage 1:

1. add/sub reuse destination capacity, including safe same-index aliases;
2. non-aliased multiplication reuses destination capacity;
3. schoolbook multiplication uses the exact maximum product width and writes
   each row's final carry directly;
4. squaring accumulates each doubled cross product once in portable base-2^32
   pieces;
5. non-aliased square operations reuse destination capacity.

Destructive multiply/square aliases retain a temporary. `bignum_reserve()` also
keeps exact-size growth rather than retaining speculative capacity that may later
hold private material.

## Benchmark result

Stage 2 compares against the exact Stage-1 add/sub/mul/square implementations.

### Improvement range across 1024/2048/3072/4096-bit cases

| Operation | Linux | macOS | Windows |
|---|---:|---:|---:|
| `add` | +47.1% to +59.4% | +46.1% to +66.1% | +40.7% to +55.6% |
| `sub` | +45.4% to +60.1% | +43.7% to +65.5% | +38.5% to +50.0% |
| `mul` | +2.8% to +18.1% | +3.2% to +10.1% | -2.0% to +10.7% |
| `square` | +54.8% to +61.8% | +15.3% to +27.5% | +41.8% to +53.9% |

The small Windows 3072-bit multiplication regression (`-2.0%`) is retained in
the record rather than hidden. Stage 2's strongest consistent gains are output
reuse for linear operations and the square-specific rewrite.

### Representative 4096-bit raw timings

| Operation | Linux | macOS | Windows |
|---|---:|---:|---:|
| `add` | 0.516 -> 0.273 us (+47.1%) | 0.479 -> 0.258 us (+46.1%) | 0.540 -> 0.320 us (+40.7%) |
| `sub` | 0.560 -> 0.306 us (+45.4%) | 0.471 -> 0.265 us (+43.7%) | 0.520 -> 0.320 us (+38.5%) |
| `mul` | 11.700 -> 11.369 us (+2.8%) | 24.191 -> 23.056 us (+4.7%) | 20.600 -> 18.400 us (+10.7%) |
| `square` | 50.926 -> 20.101 us (+60.5%) | 47.180 -> 39.960 us (+15.3%) | 50.200 -> 29.200 us (+41.8%) |

## Validation record

- final accurate benchmark run: `33800902324`
- validated code head: `293d736b22d807b554d8688dbd23849a97d7cfde`
- artifacts:
  - `bignum-stage2-accurate-Linux`
  - `bignum-stage2-accurate-macOS`
  - `bignum-stage2-accurate-Windows`

Stage 2 passed the complete CI, RSA validation, ECC validation, dedicated Bignum
Validation, and Ubuntu ASan/UBSan checks before merge.

---

# Stage 3 - measured Karatsuba dispatch

## Decision process

Stage 3 was deliberately benchmark-first rather than adding Karatsuba because
its asymptotic complexity looks better.

The experimental benchmark compared Stage-2 schoolbook multiplication against a
portable one-level Karatsuba split over 512-8192-bit operands. It measured both
reusable scratch and one-shot allocation. The experiment showed that small
operands do not justify Karatsuba, while 3072 bits and above were promising
across Linux, macOS, and Windows.

The production implementation was then added and measured again. This second
measurement is the result that determines the accepted threshold because it
includes the real dispatch, per-call workspace allocation, and secure workspace
zeroization.

## Accepted implementation

`crypto_bignum_mul()` now uses:

- **Stage-2 schoolbook** for operands below 96 limbs;
- **one-level Karatsuba** for equal-width operands at or above
  **96 limbs / 3072 bits**;
- Stage-2 schoolbook for unbalanced operands outside the measured Karatsuba
  domain;
- Stage-2 schoolbook as a safe fallback if Karatsuba workspace allocation cannot
  be completed.

The Stage-2 multiplication implementation is retained under the explicit
source-level internal name `crypto_bignum_mul_schoolbook()`. The production
`crypto_bignum_mul()` dispatcher calls that function for its baseline/fallback
paths; no CMake compile-definition symbol rewriting is required. This keeps the
same symbol graph for CMake, manual Makefile builds, IDEs, and static-analysis
tools. Generic `crypto_bignum_mod_mul()` routes through the production
multiplication dispatcher before reduction, so applicable public/general
modular multiplication can receive the Stage-3 gain.

## Final production benchmark

Positive percentages mean the final Stage-3 production dispatch is faster than
the exact Stage-2 schoolbook reference in the same process.

### Improvement at and above the production threshold

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 3072 | **+6.0%** | **+25.2%** | **+12.5%** |
| 4096 | **+13.1%** | **+30.9%** | **+17.9%** |
| 6144 | **+18.5%** | **+29.5%** | **+16.0%** |
| 8192 | **+17.2%** | **+28.1%** | **+15.4%** |

### Raw timings (`Stage 2 -> Stage 3`, microseconds per multiplication)

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 3072 | 7.140 -> 6.710 | 12.348 -> 9.239 | 12.000 -> 10.500 |
| 4096 | 13.178 -> 11.454 | 23.107 -> 15.973 | 23.333 -> 19.167 |
| 6144 | 28.607 -> 23.310 | 55.987 -> 39.452 | 41.667 -> 35.000 |
| 8192 | 50.320 -> 41.657 | 102.397 -> 73.626 | 74.286 -> 62.857 |

The threshold therefore survives the final production measurement: **3072 bits
is faster on all three hosted operating systems even after allocation and secure
zeroization costs are included**. The margin then grows at larger operand sizes.

Below the threshold, the production dispatcher selects the Stage-2 function;
small differences in repeated timing are runner/timer noise rather than a
separate arithmetic implementation.

## Stage-3 validation record

Final production code head:

- `b8752b6608708fedd618180e51f6146eb6f4bf75`

Validation:

- Bignum Validation run `33818440244`: complete test suite on Linux/macOS/Windows,
  final production benchmark on all three OS runners, and Ubuntu ASan/UBSan;
- RSA validation run `33818440271`;
- ECC validation run `33818440257`;
- general CI run `33818440245`.

Final benchmark artifacts:

- `bignum-stage3-production-Linux`
- `bignum-stage3-production-macOS`
- `bignum-stage3-production-Windows`

The benchmark also differential-checks the production dispatcher against the
exact Stage-2 multiplier across 1-160 equal-width limbs and verifies destructive
left/right alias cases before timing.

---

# Reading the optimization history

The intended stage snapshots are:

| Tag | Meaning |
|---|---|
| `bignum-stage0-baseline` | repository immediately before Stage 1 |
| `bignum-stage1-reduction-montgomery` | accepted Stage-1 reduction/Montgomery implementation |
| `bignum-stage2-mul-square` | accepted Stage-2 output-reuse/mul/square implementation |
| `bignum-stage3-karatsuba` | accepted Stage-3 production Karatsuba dispatch |

Use the tags for exact historical source comparisons and the benchmark artifacts
for measured evidence. Do not multiply speedup ratios from different stages:
Stage 1, Stage 2, and Stage 3 measure different operations and were run in
separate hosted-runner jobs.
