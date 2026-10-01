#!/usr/bin/env bash
set -euo pipefail
export OMPI_MCA_btl=^openib

ROOT="${ROOT:-/home/liuliangxin/Code-Based-Scalable-coSNARKs-main}"
LIB="${LIB:-}"
PROOF_SYSTEM_ID="${PROOF_SYSTEM_ID:-}"
NP="${NP:-4}"
BUILD="${BUILD:-0}"
REUSE_PROVIDER_PROBE="${REUSE_PROVIDER_PROBE:-0}"
NORMAL_RESUME="${NORMAL_RESUME:-0}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/experiments/results/provider_candidate_acceptance_$STAMP}"

if [[ -z "$LIB" || -z "$PROOF_SYSTEM_ID" ]]; then
  echo "LIB and PROOF_SYSTEM_ID are required" >&2
  exit 2
fi
if [[ ! -f "$LIB" ]]; then
  echo "provider library not found: $LIB" >&2
  exit 2
fi
if [[ "$NP" -ne 4 ]]; then
  echo "provider candidate acceptance currently uses NP=4" >&2
  exit 2
fi

TOTAL_CPUS="$(nproc)"
DEFAULT_THREADS=$(( TOTAL_CPUS / NP ))
if [[ "$DEFAULT_THREADS" -lt 1 ]]; then
  DEFAULT_THREADS=1
fi
PVIA_PROVIDER_THREADS="${PVIA_PROVIDER_THREADS:-$DEFAULT_THREADS}"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-$PVIA_PROVIDER_THREADS}"

mkdir -p "$OUT"
cd "$ROOT"

case "$BUILD" in
  1) cmake --build build-pvia -j2 > "$OUT/build.log" 2>&1 ;;
  0) printf 'build skipped by caller\n' > "$OUT/build.log" ;;
  *) echo "BUILD must be 0 or 1" >&2; exit 2 ;;
esac

if [[ "$REUSE_PROVIDER_PROBE" == "1" ]]; then
  if [[ ! -f "$OUT/provider_probe.log" ]] ||
     ! grep -q '\[PVIA\]\[consistency-provider-probe\] PASS' "$OUT/provider_probe.log"; then
    echo "REUSE_PROVIDER_PROBE=1 requires an existing PASS provider_probe.log" >&2
    exit 4
  fi
  echo "reused completed provider probe" > "$OUT/provider_probe_reuse.log"
else
  mpirun -np "$NP" env \
    PVIA_ENABLE=1 \
    "PVIA_MC_PROVIDER_LIBRARY=$LIB" \
    "PVIA_MC_PROVIDER_PROOF_SYSTEM_ID=$PROOF_SYSTEM_ID" \
    ./build-pvia/src/pigeon 7 0 \
    > "$OUT/provider_probe.log" 2>&1
fi

grep -q '\[PVIA\]\[consistency-provider-probe\] PASS' "$OUT/provider_probe.log"

export PVIA_MC_PROVIDER_LIBRARY="$LIB"
export PVIA_MC_PROVIDER_PROOF_SYSTEM_ID="$PROOF_SYSTEM_ID"

NORMAL_OUT="$OUT/normal_path"
NP="$NP" REPEATS=1 WARMUP=0 \
M_LOG=9 SUMCHECK_LOG=7 PC_LOG=8 MULTREE_LOG=5 \
BUILD=0 RESUME="$NORMAL_RESUME" OUT="$NORMAL_OUT" \
  bash experiments/run_copiop_overhead_xfusion.sh \
  > "$OUT/normal_path_runner.log" 2>&1

python3 - "$NORMAL_OUT/SUMMARY.txt" "$OUT/provider_probe.log" "$NP" > "$OUT/runtime_check.log" <<'PY'
import re
import sys
from pathlib import Path

summary = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        summary[key.strip()] = value.strip()
probe_text = Path(sys.argv[2]).read_text(errors="replace")
np = int(sys.argv[3])
expected = {
    "enabled_consistency_provider_present": 1,
    "enabled_consistency_provider_production_ready": 1,
    "enabled_consistency_provider_acceptance_present": 1,
    "enabled_consistency_provider_active": 1,
    "enabled_initial_validity_strong_active": 1,
    "enabled_initial_validity_strong_run_rank_count": np,
}
for key, wanted in expected.items():
    if key not in summary:
        raise SystemExit(f"missing summary field: {key}")
    actual = int(float(summary[key]))
    if actual != wanted:
        raise SystemExit(f"{key}: expected {wanted}, got {actual}")
runtime_protocol_id = int(float(
    summary.get("enabled_consistency_provider_protocol_id", "0")))
if runtime_protocol_id <= 0:
    raise SystemExit("provider protocol id was not recorded")
match = re.search(
    r"consistency-provider-probe\] PASS protocol_id=(\d+)",
    probe_text)
if not match:
    raise SystemExit("provider probe protocol id was not recorded")
probe_protocol_id = int(match.group(1))
if runtime_protocol_id != probe_protocol_id:
    raise SystemExit(
        "provider protocol id mismatch: "
        f"runtime={runtime_protocol_id} probe={probe_protocol_id}")
print(
    "PROVIDER_CANDIDATE_RUNTIME: PASS "
    f"protocol_id={runtime_protocol_id} ranks={np}")
PY

{
  echo 'PROVIDER_CANDIDATE_ACCEPTANCE: PASS'
  grep '\[PVIA\]\[consistency-provider-probe\] PASS'     "$OUT/provider_probe.log" | tail -1
  cat "$OUT/runtime_check.log"
  echo "library=$LIB"
  echo "proof_system_id=$PROOF_SYSTEM_ID"
  echo "rayon_threads=$RAYON_NUM_THREADS"
  echo "results=$OUT"
} | tee "$OUT/SUMMARY.txt"
