#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-/home/liuliangxin/Code-Based-Scalable-coSNARKs-main}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/experiments/results/copiop_green_gate_$STAMP}"
MATRIX_OUT="$OUT/matrix"
mkdir -p "$OUT"
cd "$ROOT"

python3 experiments/check_protocol_code_mapping.py \
  --root "$ROOT" --map notes/PAPPAS_PROTOCOL_CODE_MAP.csv \
  > "$OUT/mapping.log"
grep -q '^PROTOCOL_CODE_MAPPING: PASS' "$OUT/mapping.log"

python3 experiments/check_private_epoch_transport_coverage.py \
  --root "$ROOT" --map notes/PVIA_PRIVATE_EPOCH_TRANSPORT_MAP.csv \
  > "$OUT/private_epoch_transport.log"

python3 experiments/check_consistency_backend_readiness.py \
  --root "$ROOT" > "$OUT/consistency_backend_readiness.log"
grep -q '^CONSISTENCY_BACKEND_READINESS:' \
  "$OUT/consistency_backend_readiness.log"
grep -q '^PRIVATE_EPOCH_TRANSPORT_COVERAGE: PASS' \
  "$OUT/private_epoch_transport.log"

MODE=regression OUT="$MATRIX_OUT" \
  bash experiments/run_copiop_regression_matrix_xfusion.sh \
  > "$OUT/matrix_runner.log" 2>&1
grep -q '^COPIOP_REGRESSION_MATRIX: PASS' "$OUT/matrix_runner.log"

PROVIDER_STATUS_OUT="$OUT/provider_status"
BUILD=0 OUT="$PROVIDER_STATUS_OUT"   bash experiments/run_consistency_provider_status_smoke_xfusion.sh   > "$OUT/provider_status_runner.log" 2>&1
grep -q '^CONSISTENCY_PROVIDER_STATUS_SMOKE: PASS'   "$PROVIDER_STATUS_OUT/SUMMARY.txt"

PROVIDER_VECTOR_OUT="$OUT/provider_relation_vectors"
BUILD=0 OUT="$PROVIDER_VECTOR_OUT"   bash experiments/run_provider_relation_vector_export_xfusion.sh   > "$OUT/provider_relation_vectors_runner.log" 2>&1
grep -q '^PROVIDER_RELATION_VECTOR_EXPORT: PASS'   "$PROVIDER_VECTOR_OUT/SUMMARY.txt"

FAILURE_NF_OUT="$OUT/failure_no_framing"
BUILD=0 OUT="$FAILURE_NF_OUT"   bash experiments/run_failure_no_framing_matrix_xfusion.sh   > "$OUT/failure_no_framing_runner.log" 2>&1
grep -q '^PVIA FAILURE NO-FRAMING MATRIX: PASS'   "$FAILURE_NF_OUT/SUMMARY.txt"

LOCALIZATION_SMOKE_OUT="$OUT/localization_scaling_smoke"
BUILD=0 REPEATS=1 WARMUP=0 Q_SIZES="8"   OUT="$LOCALIZATION_SMOKE_OUT"   bash experiments/run_localization_scaling_xfusion.sh   > "$OUT/localization_scaling_smoke_runner.log" 2>&1
grep -q '^PVIA LOCALIZATION SCALING: PASS'   "$LOCALIZATION_SMOKE_OUT/SUMMARY.txt"
grep -q '^q8_first_depth=3$' "$LOCALIZATION_SMOKE_OUT/SUMMARY.txt"
grep -q '^q8_first_subset_checks=3$' "$LOCALIZATION_SMOKE_OUT/SUMMARY.txt"
grep -q '^q8_last_depth=3$' "$LOCALIZATION_SMOKE_OUT/SUMMARY.txt"
grep -q '^q8_last_subset_checks=6$' "$LOCALIZATION_SMOKE_OUT/SUMMARY.txt"

LOCALIZATION_NP8_OUT="$OUT/localization_np8_smoke"
NP=8 BUILD=0 REPEATS=1 WARMUP=0 Q_SIZES="32" OUT="$LOCALIZATION_NP8_OUT" bash experiments/run_localization_scaling_xfusion.sh > "$OUT/localization_np8_smoke_runner.log" 2>&1
grep -q '^PVIA LOCALIZATION SCALING: PASS' "$LOCALIZATION_NP8_OUT/SUMMARY.txt"
grep -q '^np=8$' "$LOCALIZATION_NP8_OUT/SUMMARY.txt"
grep -q '^q32_first_depth=5$' "$LOCALIZATION_NP8_OUT/SUMMARY.txt"
grep -q '^q32_last_depth=5$' "$LOCALIZATION_NP8_OUT/SUMMARY.txt"

RELEASE_GATE_OUT="$OUT/release_gate_matrix"
BUILD=0 OUT="$RELEASE_GATE_OUT"   bash experiments/run_release_gate_matrix_xfusion.sh   > "$OUT/release_gate_matrix_runner.log" 2>&1
grep -q '^PVIA RELEASE GATE MATRIX: PASS' "$RELEASE_GATE_OUT/SUMMARY.txt"
grep -q '^claim_scope=release-gate-withholding-semantics$'   "$RELEASE_GATE_OUT/SUMMARY.txt"

python3 experiments/check_paper_implementation_alignment.py \
  --root "$ROOT" --alignment notes/PVIA_PAPER_IMPLEMENTATION_ALIGNMENT.csv \
  > "$MATRIX_OUT/paper_alignment.log"
grep -q '^PAPER_IMPLEMENTATION_ALIGNMENT: PASS' "$MATRIX_OUT/paper_alignment.log"
cp "$OUT/private_epoch_transport.log" "$MATRIX_OUT/private_epoch_transport.log"
cp "$OUT/consistency_backend_readiness.log" \
  "$MATRIX_OUT/consistency_backend_readiness.log"
cp "$PROVIDER_STATUS_OUT/SUMMARY.txt"   "$MATRIX_OUT/provider_status_smoke.log"
cp "$PROVIDER_VECTOR_OUT/SUMMARY.txt"   "$MATRIX_OUT/provider_relation_vectors.log"
cp "$FAILURE_NF_OUT/SUMMARY.txt" "$MATRIX_OUT/failure_no_framing.log"

cp "$LOCALIZATION_SMOKE_OUT/SUMMARY.txt"   "$MATRIX_OUT/localization_scaling_smoke.log"

cp "$RELEASE_GATE_OUT/SUMMARY.txt"   "$MATRIX_OUT/release_gate_matrix.log"
cp "$LOCALIZATION_NP8_OUT/SUMMARY.txt"   "$MATRIX_OUT/localization_np8_smoke.log"

python3 experiments/create_green_checkpoint.py \
  --root "$ROOT" --matrix-dir "$MATRIX_OUT" --mode regression \
  --output "$OUT/green_checkpoint.json" \
  --markdown "$OUT/GREEN_CHECKPOINT.md" \
  > "$OUT/checkpoint.log"
grep -q '^COPIOP_GREEN_CHECKPOINT: PASS' "$OUT/checkpoint.log"

cp "$MATRIX_OUT/regression_matrix.csv" "$OUT/regression_matrix.csv"
cp "$MATRIX_OUT/regression_matrix.md" "$OUT/regression_matrix.md"

echo 'COPIOP_GREEN_GATE: PASS'
echo "checkpoint=$OUT/green_checkpoint.json"
echo "summary=$OUT/GREEN_CHECKPOINT.md"
echo "results=$OUT"
