# Paper-aligned M_LOG=18 baseline -> PVIA comparison

Same host/binary/parameters within each paired batch. This is a single-host MPI incremental-accountability comparison, not a reproduction of the original paper's absolute LAN/WAN timings.

| N | Base E2E s | PVIA E2E s | E2E median delta | Rank0 median delta | Verifier median delta | Proof median delta | Native rounds delta | Ctrl syncs/rank |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | 16.63 | 19.45 | 17.0% | 27.9% | 9.4% | -0.0% | 0 | 31 |
| 8 | 8.91 | 10.73 | 20.3% | 27.3% | -21.3% | 0.7% | 0 | 29 |
| 16 | 5.25 | 7.69 | 46.5% | 40.6% | 7.2% | -0.5% | 0 | 27 |

| N | Native/legacy MB | Legacy delta | Added online MB | Added full MB | PVIA full instrumented MB | Instrumented factor |
|---:|---:|---:|---:|---:|---:|---:|
| 4 | 58.264 | 0.0% | 156.490 | 159.374 | 217.638 | 3.74x |
| 8 | 60.356 | 0.0% | 365.777 | 377.946 | 438.302 | 7.26x |
| 16 | 62.054 | 0.0% | 789.683 | 836.303 | 898.357 | 14.48x |
