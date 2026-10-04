# PVIA on Code-Based Scalable Collaborative SNARKs

This repository contains the **primary PVIA implementation and evaluation artifact** used in our research prototype. PVIA is integrated into a code-based scalable collaborative SNARK implementation and adds release checks, execution/context binding, public verification support, and private failure localization around security-relevant protocol outputs.

The repository is intended for **research, reproducibility, and artifact evaluation**. It is not a production deployment.

## What is included

The repository contains:

- the underlying code-based collaborative proving implementation;
- the active PVIA implementation under `src/accountability/`;
- PVIA integration points in the collaborative proving pipeline;
- baseline-vs.-PVIA performance runners;
- release-check and context-binding validation;
- failure-path and public-verification benchmarks;
- private localization experiments;
- SP1-based consistency-provider source and relation tests;
- curated CSV / Markdown / LaTeX results used by the paper.

The main protocol integration points are:

```text
src/coPIOP.cpp
src/coPCS.cpp
src/coSumcheck_MPI.cpp
src/Distributed_Sumcheck.cpp
src/MPI_utils.cpp
src/MPI_utils.hpp
src/main.cpp
src/CMakeLists.txt
```

The PVIA-specific implementation is under:

```text
src/accountability/
```

## Evaluation structure

The evaluation has two roles:

1. **This repository** is the primary, full implementation used for end-to-end overhead measurements.
2. A structurally different PSS/HyperPlonk implementation is used as a lightweight second-instantiation applicability test:

   https://github.com/liuliangxin/Scalable-Collaborative-zkSNARK

The second repository should not be interpreted as a second full end-to-end performance benchmark.

## Tested environment

The paper measurements were collected on:

```text
OS: Linux 5.4
CPU: 2 x Intel Xeon Gold 6330 @ 2.00 GHz
Cores/socket: 28
Hardware threads: 112
RAM: 251 GiB

GCC: 9.4.0
Open MPI: 4.0.3
CMake: 3.17.2
OpenSSL: 1.1.1f
```

Other recent Linux environments may work, but the fixed paper results were produced with the configuration above.

## Dependencies

On Ubuntu 20.04 or a similar distribution:

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  cmake \
  openmpi-bin \
  libopenmpi-dev \
  libssl-dev \
  python3 \
  python3-pip \
  git \
  curl \
  pkg-config
```

Check the main tools:

```bash
g++ --version
cmake --version
mpirun --version
openssl version
python3 --version
```

## Build

From the repository root:

```bash
cmake -S . -B build-pvia
cmake --build build-pvia -j2
```

The main executable should be:

```bash
test -x build-pvia/src/pigeon && echo BUILD_OK
```

Expected:

```text
BUILD_OK
```

## Quick smoke test: baseline vs. PVIA

For a short local validation:

```bash
OUT="$PWD/experiments/results/manual_overhead_$(date +%Y%m%d_%H%M%S)"

NP=4 \
REPEATS=1 \
WARMUP=0 \
M_LOG=10 \
SUMCHECK_LOG=8 \
PC_LOG=9 \
MULTREE_LOG=6 \
BUILD=1 \
OUT="$OUT" \
bash experiments/run_copiop_overhead_xfusion.sh
```

Inspect:

```bash
cat "$OUT/SUMMARY.txt"
cat "$OUT/raw_runs.csv"
```

Expected status marker:

```text
PVIA coPIOP OVERHEAD: PASS
```

The runner executes the same implementation with PVIA disabled and enabled, which provides the controlled baseline comparison used throughout the evaluation.

## Paper-aligned primary experiment

The headline workload uses:

```text
M_LOG=18
SUMCHECK_LOG=14
PC_LOG=15
MULTREE_LOG=10
N = 4, 8, 16
1 warm-up
5 measured pairs
```

Run:

```bash
OUT="$PWD/experiments/results/manual_paper_aligned_$(date +%Y%m%d_%H%M%S)"

PARTIES="4 8 16" \
REPEATS=5 \
WARMUP=1 \
BUILD=1 \
OUT="$OUT" \
bash experiments/run_pappas_aligned_accountability_xfusion.sh
```

Generate the compact comparison:

```bash
python3 experiments/build_paper_aligned_m18_comparison.py \
  --results "$OUT" \
  --out experiments/results/manual_paper_aligned_comparison
```

### Fixed paper results

The curated uninstrumented result is stored under:

```text
experiments/results/pvia_paper_aligned_m18_comparison_20260929/
```

The measured median end-to-end overheads are approximately:

| Parties | Baseline E2E | PVIA E2E | Median overhead |
|---:|---:|---:|---:|
| 4 | 16.63 s | 19.45 s | 17.0% |
| 8 | 8.91 s | 10.73 s | 20.3% |
| 16 | 5.25 s | 7.69 s | 46.5% |

These are **single-host paired measurements** and are intended to measure incremental PVIA cost under a controlled environment. They are not a reproduction of the original system's LAN/WAN absolute performance.

## Cost attribution

The integrated attribution results are under:

```text
experiments/results/pvia_accountability_cost_attribution_20260929/
```

Inspect:

```bash
cat experiments/results/pvia_accountability_cost_attribution_20260929/SUMMARY.txt
cat experiments/results/pvia_accountability_cost_attribution_20260929/accountability_cost_attribution.csv
```

Important interpretation rule:

- the **uninstrumented paper-aligned batch** is the headline performance source;
- the timing-instrumented batch is diagnostic only;
- metadata observation already contains verification work and must not be double-counted.

## Release-check validation

Run:

```bash
OUT="$PWD/experiments/results/manual_release_gate_$(date +%Y%m%d_%H%M%S)"

BUILD=1 \
OUT="$OUT" \
bash experiments/run_release_gate_matrix_xfusion.sh
```

Expected marker:

```text
PVIA RELEASE GATE MATRIX: PASS
```

The test covers representative release families including collaborative Sumcheck, distributed Sumcheck, encoding, PCS opening, and batched PCS opening.

For each covered family:

```text
normal case   -> ALLOW
modified case -> WITHHOLD
scope binding -> BOUND
```

## Context-binding validation

Run:

```bash
OUT="$PWD/experiments/results/manual_context_$(date +%Y%m%d_%H%M%S)"

BUILD=1 \
OUT="$OUT" \
bash experiments/run_failure_no_framing_matrix_xfusion.sh
```

The historical curated result is under:

```text
experiments/results/failure_no_framing_20260929_023154/
```

The matrix checks normal acceptance together with wrong-session, modified evidence, registry-anchor, transport-scope, and state-consistency rejection cases.

## Failure-path measurements

Failure-resolution latency:

```bash
OUT="$PWD/experiments/results/manual_abort_$(date +%Y%m%d_%H%M%S)"

NP=4 \
REPEATS=10 \
WARMUP=1 \
OUT="$OUT" \
bash experiments/run_abort_latency_xfusion.sh
```

Public verification benchmark:

```bash
OUT="$PWD/experiments/results/manual_judge_$(date +%Y%m%d_%H%M%S)"

BATCHES=10 \
INNER_REPEATS=1000 \
WARMUP=1 \
OUT="$OUT" \
bash experiments/run_robust_abort_judge_benchmark_xfusion.sh
```

The paper reports approximately:

```text
covered rejecting path mean: 9.09 ms
covered rejecting path p95:  11.61 ms
replay/control rejection:     4.14 ms
public verification:          0.776 ms
```

These costs belong to rejecting executions and are not added to successful-prover E2E overhead.

## Private localization

### Scaling with the candidate set

```bash
OUT="$PWD/experiments/results/manual_localization_$(date +%Y%m%d_%H%M%S)"

NP=4 \
REPEATS=10 \
WARMUP=2 \
Q_SIZES="4 8 16 32 64" \
BUILD=1 \
OUT="$OUT" \
bash experiments/run_localization_scaling_xfusion.sh
```

Curated result:

```text
experiments/results/localization_scaling_20260929_033340/
```

Measured recursive depths:

```text
Q=4   -> depth 2
Q=8   -> depth 3
Q=16  -> depth 4
Q=32  -> depth 5
Q=64  -> depth 6
```

The experimental claim is logarithmic recursive depth / subset-check count in `Q`. It is **not** a claim that wall-clock time is `O(log Q)`.

### Scaling with the number of parties

```bash
OUT="$PWD/experiments/results/manual_localization_parties_$(date +%Y%m%d_%H%M%S)"

PARTIES="4 8 16" \
Q=32 \
REPEATS=5 \
WARMUP=1 \
BUILD=1 \
OUT="$OUT" \
bash experiments/run_localization_party_scaling_xfusion.sh
```

Curated result:

```text
experiments/results/localization_party_scaling_20260929_035843/
```

## External consistency provider

The repository also contains the source and relation tests for the SP1-based consistency provider under:

```text
experiments/sp1_provider/
```

This provider is evaluated separately from the paired native-prover fast path. Its activation/proving cost must not be folded into the headline baseline-vs.-PVIA numbers unless explicitly measured in a separate experiment.

## Repository layout

```text
src/
  accountability/           PVIA implementation
  coPIOP.cpp                 protocol integration
  coPCS.cpp                  protocol integration
  coSumcheck_MPI.cpp         protocol integration
  Distributed_Sumcheck.cpp  protocol integration
  MPI_utils.*                communication integration
  main.cpp                   runtime integration

experiments/
  run_copiop_overhead_xfusion.sh
  run_pappas_aligned_accountability_xfusion.sh
  run_release_gate_matrix_xfusion.sh
  run_failure_no_framing_matrix_xfusion.sh
  run_abort_latency_xfusion.sh
  run_robust_abort_judge_benchmark_xfusion.sh
  run_localization_scaling_xfusion.sh
  run_localization_party_scaling_xfusion.sh
  build_paper_aligned_m18_comparison.py
  build_accountability_cost_attribution.py
  results/

pvia-evaluation/
  README.md
```

## Reproducibility notes

Please keep the following distinctions when reproducing or citing results:

1. Use the uninstrumented paper-aligned batch for headline overhead.
2. The small-workload sweep is a robustness/scaling check; fixed costs dominate its percentages.
3. Native prover communication is distinct from fully accounted PVIA traffic.
4. A component's share of directly timed PVIA work is not automatically its share of total E2E slowdown.
5. External provider activation is evaluated separately.
6. New experiments should use new `OUT=...` directories rather than overwriting the fixed result folders.

## Second instantiation

The lightweight PSS/HyperPlonk applicability evaluation lives in:

https://github.com/liuliangxin/Scalable-Collaborative-zkSNARK

That repository contains two final examples:

```text
hyperplonk/examples/pvia_light_eval.rs
hyperplonk/examples/pvia_commit_sanity.rs
```

## Research-use notice

This repository is a research artifact. It has not been prepared as a production security library and should not be deployed as one without an independent engineering and security review.
