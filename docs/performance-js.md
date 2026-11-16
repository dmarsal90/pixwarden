# JavaScript performance baseline

This is a reproducible microbenchmark record, not a release target or a production workload claim. Run `npm run benchmark` from the repository root to rebuild and repeat it. The command consumes four hash-pinned small shared corpus vectors and constructs synthetic 1 MiB PNG ancillary-data and JPEG comment cases. It performs 20 warm-up scans per case, then records median/p95 scan latency and mean throughput. RSS delta is process-wide before/after the sample loop; it is not peak memory or a per-scan allocation measurement.

## Recorded run

| Field | Value |
|---|---|
| Date | 2026-11-16 |
| Node.js | v22.22.2 |
| V8 | 12.4.254.21-node.39 |
| Platform | linux-x64 |
| CPU | AMD Ryzen 5 5500U with Radeon Graphics |
| Reported physical memory | 24,507,215,872 bytes |
| Shared corpus | 1.0.39 |
| Warm-up | 20 scans per case |
| Samples | 500 small cases; 100 1 MiB cases |

| Case | Input bytes | Median | p95 | Mean scans/sec | RSS delta |
|---|---:|---:|---:|---:|---:|
| PNG shared vector | 58 | 0.042 ms | 0.081 ms | 19,258.1 | 286,720 bytes |
| GIF shared vector | 28 | 0.028 ms | 0.044 ms | 31,182.3 | 0 bytes |
| JPEG shared vector | 19 | 0.029 ms | 0.049 ms | 28,642.4 | 917,504 bytes |
| WebP shared vector | 24 | 0.030 ms | 0.050 ms | 27,069.3 | 733,184 bytes |
| PNG ancillary metadata | 1,048,646 | 68.393 ms | 89.167 ms | 13.9 | 42,856,448 bytes |
| JPEG comments | 1,048,611 | 77.071 ms | 84.376 ms | 12.9 | 1,048,576 bytes |

The corpus cases are deliberately tiny; the two generated 1 MiB cases exercise bounded metadata and full chunk/segment walks. Results vary with CPU scheduling, runtime version, and garbage collection. The RSS deltas include allocation and collection behavior across the entire loop. No CPU/RSS quota, throughput SLA, or production capacity is established by this run.

During this review, the PNG 1 MiB case measured 102.813 ms median before and 65.393 ms after replacing the per-bit CRC loop with a lookup table (about 36% lower in those two runs). The JPEG case measured 75.188 ms and 75.565 ms respectively, as expected because it does not use PNG CRC. This is a single before/after sample and should be repeated on target hardware before using it as a performance claim.
