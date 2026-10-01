# PVIA evaluation artifact

This branch contains the active PVIA implementation plus the curated files used to reproduce the paper evaluation.

Included:
- active `src/accountability/` source files;
- protocol integration files under `src/`;
- paper-aligned performance runners and analysis scripts;
- release-validation, context-validation, public-verification, localization, and regression runners;
- SP1 provider source/configuration and relation tests;
- curated CSV, Markdown, LaTeX, and summary results.

Excluded:
- `.bak`, `.tmp`, and backup directories;
- build directories and caches;
- compiled shared libraries, ELF files, and proof binaries;
- bulk debug logs and abandoned intermediate runs.

Primary paper result:
`experiments/results/pvia_paper_aligned_m18_comparison_20260929/`

Integrated cost attribution:
`experiments/results/pvia_accountability_cost_attribution_20260929/`

Localization results:
`experiments/results/localization_scaling_20260929_033340/`
and
`experiments/results/localization_party_scaling_20260929_035843/`

Build:
```bash
cmake -S . -B build-pvia
cmake --build build-pvia -j2
```

Main paired run:
```bash
OUT="$PWD/experiments/results/manual_paper_aligned_$(date +%Y%m%d_%H%M%S)"
PARTIES="4 8 16" REPEATS=5 WARMUP=1 BUILD=1 OUT="$OUT" \
  bash experiments/run_pappas_aligned_accountability_xfusion.sh
```
