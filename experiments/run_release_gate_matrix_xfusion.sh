#!/usr/bin/env bash
set -euo pipefail
export OMPI_MCA_btl=^openib
ROOT="${ROOT:-/home/liuliangxin/Code-Based-Scalable-coSNARKs-main}"
BUILD="${BUILD:-0}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/experiments/results/release_gate_matrix_$STAMP}"
TMP="$(mktemp -d /tmp/pvia-release-gate-matrix.XXXXXX)"
mkdir -p "$OUT"

cd "$ROOT"
case "$BUILD" in
  1) cmake --build build-pvia -j2 > "$OUT/build.log" 2>&1 ;;
  0) printf 'build skipped by caller\n' > "$OUT/build.log" ;;
  *) echo "BUILD must be 0 or 1" >&2; exit 2 ;;
esac

for r in 0 1 2 3; do
  umask 077
  openssl rand -hex 32 > "$TMP/rank_${r}.key"
done

mpirun -np 4 env \
  PVIA_ENABLE=1 \
  PVIA_SESSION_ID=532001 \
  PVIA_RELEASE_GATE_MATRIX_SELFTEST=1 \
  "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key" \
  ./build-pvia/src/pigeon 2 0 > "$OUT/run.log" 2>&1

for family in cosumcheck distributed-sumcheck encoding pcs-open pcs-batch-open; do
  grep -q "\[PVIA\]\[release-gate-matrix\] family=$family .*positive=ALLOW injected=WITHHOLD exact-scope=BOUND result=PASS" "$OUT/run.log"
done
grep -q '\[PVIA\]\[release-gate-matrix-summary\] cases=5 private-localization=folding-only other-families=release-blocking-only result=PASS' "$OUT/run.log"

cat > "$OUT/SUMMARY.txt" <<EOF
PVIA RELEASE GATE MATRIX: PASS
np=4
cases=5
cosumcheck_positive=ALLOW
cosumcheck_injected=WITHHOLD
distributed_sumcheck_positive=ALLOW
distributed_sumcheck_injected=WITHHOLD
encoding_positive=ALLOW
encoding_injected=WITHHOLD
pcs_open_positive=ALLOW
pcs_open_injected=WITHHOLD
pcs_batch_open_positive=ALLOW
pcs_batch_open_injected=WITHHOLD
exact_scope=BOUND
private_localization=folding-only
other_families=release-blocking-only
decision_backend=test-only
claim_scope=release-gate-withholding-semantics
EOF
cat "$OUT/SUMMARY.txt"
echo "results=$OUT"
