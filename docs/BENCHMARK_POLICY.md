# Benchmark Framework Policy

**Last updated**: 2026-03-15

---

## Canonical Benchmark Binary

**`bench_unified`** is the ONLY accepted CPU benchmark tool.

| Name | Status | Purpose |
|------|--------|---------|
| `bench_unified` | Canonical | All CPU operations: field, scalar, point, ECDSA, Schnorr, CT, comparison |
| `bench_hornet` | ESP32-only | Embedded port of bench format for ESP32-S3/P4/C6 |
| `bench_comprehensive` | RETIRED | Former name, all references updated to `bench_unified` |

### 8 Benchmark Categories (all must produce data)

1. Field arithmetic (mul, sqr, inv, add, sub, negate)
2. Scalar arithmetic (mul, inv, add, negate)
3. Point arithmetic (k*G, k*P, a*G+b*P, add, dbl)
4. ECDSA (sign FAST, verify)
5. Schnorr / BIP-340 (keypair, sign FAST, verify)
6. Constant-time (CT sign ECDSA, CT sign Schnorr, overhead ratios)
7. libsecp256k1 comparison (same ops, direct ratio)
7.5. OpenSSL comparison (ECDSA, system library)
8. Apple-to-Apple ratio table

---

## Regression Gate

### GitHub Actions (`bench-regression.yml`)

- **Trigger**: Push to main/dev (path-filtered), PR to main, manual dispatch
- **Threshold**: 200% (operation must be >2x slower to fail)
- **Enforcement**: `fail-on-alert: true` -- no `continue-on-error`
- **Baseline**: Stored on gh-pages, auto-updated on push events
- **PR behavior**: Read-only comparison, blocks on regression

### Why 200% Threshold?

Shared CI runners have up to ~60% variance due to CPU frequency scaling, neighbor noise, and thermal throttling. A 200% threshold safely catches real regressions (>100% slower) while avoiding false positives from runner variance.

---

## Execution Profile

| Parameter | Value |
|-----------|-------|
| Warmup | 500 iterations |
| Passes | 11 (default), 3 (--quick) |
| Outlier removal | IQR method |
| Metric | Median of passes |
| Key pool | 64 pre-generated keys |
| Thread | Single-threaded, no pinning on CI |

For authoritative benchmarks (release reports), use dedicated hardware with core pinning:
```bash
taskset -c 0 ./bench_unified --passes 11 --json report.json
```

---

## Blocking vs Informational Operations

### Blocking (included in regression gate)

All operations from categories 1-6 above with >50 ns median are included in the regression comparisons. Sub-50 ns operations (e.g., field_add, field_sub) are excluded because:
- Measurement noise dominates at very low durations
- These are leaf operations whose regression would be caught via their callers (e.g., point_mul)

### Informational (not in regression gate)

| Operation | Reason |
|-----------|--------|
| libsecp256k1 comparison ratios | External library, not our regression |
| OpenSSL comparison ratios | External library |
| MICRO-DIAGNOSTICS section | Diagnostic/derived values |
| Sub-50 ns primitives | Noise-dominated |

---

## JSON Schema

Benchmark output JSON entries must contain:

```json
{
  "name": "string",
  "unit": "ns/op",
  "value": 123.45
}
```

The parser (`parse_benchmark.py`) performs a hard `exit(1)` if zero entries are parsed -- no dummy entries are ever produced.

---

## Baseline Policy

| Event | Baseline Action |
|-------|----------------|
| Push to main/dev | Store new baseline (auto-push to gh-pages) |
| Pull request | Read-only comparison (no baseline update) |
| Manual dispatch | Store new baseline (reset capability) |
| Release tag | No action (audit-report.yml runs instead) |

Baseline is stored per-branch in `dev/bench-gate` on the gh-pages branch.

---

## Docs Mapping

| Document | Purpose | Canonical? |
|----------|---------|-----------|
| `BENCHMARKS.md` | Results and analysis (historical data) | Yes |
| `BENCHMARKING.md` | How to run benchmarks (usage guide) | Yes |
| `BENCHMARK_METHODOLOGY.md` | Statistical methodology (warmup, IQR, passes) | Yes |
| `PERFORMANCE_REGRESSION.md` | Regression detection policy and CI gate | Yes |
| `PERFORMANCE_GUIDE.md` | Tuning guide for users | Yes |
