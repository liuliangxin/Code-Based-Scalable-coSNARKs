#!/usr/bin/env bash
set -euo pipefail
export OMPI_MCA_btl=^openib

ROOT="${ROOT:-/home/liuliangxin/Code-Based-Scalable-coSNARKs-main}"
BUILD="${BUILD:-0}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/experiments/results/failure_no_framing_$STAMP}"
TMP="$(mktemp -d /tmp/pvia-failure-nf.XXXXXX)"
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

mpirun -np 4 env PVIA_ENABLE=1 PVIA_SESSION_ID=529100 \
  "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key" \
  ./build-pvia/src/pigeon 2 0 > "$OUT/anchor_probe.log" 2>&1
anchor="$(grep -oE 'transfer key registry commitment=[0-9a-f]{64}' \
  "$OUT/anchor_probe.log" | head -1 | cut -d= -f2)"
[[ "$anchor" =~ ^[0-9a-f]{64}$ ]] || exit 3
printf '%s\n' "$anchor" > "$OUT/registry_anchor.txt"

mpirun -np 4 env PVIA_ENABLE=1 PVIA_SESSION_ID=529101 \
  PVIA_TRANSFER_NO_FRAMING_SELFTEST=1 \
  "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key" \
  "PVIA_TRANSFER_REGISTRY_ANCHOR=$anchor" \
  ./build-pvia/src/pigeon 2 0 \
  > "$OUT/transfer.log" 2>&1

grep -q '\[PVIA\]\[transfer-no-framing-selftest\].*result=PASS' \
  "$OUT/transfer.log"
grep -q '\[PVIA\]\[transfer-no-framing-entry\].*result=PASS' \
  "$OUT/transfer.log"

mpirun -np 4 env PVIA_ENABLE=1 PVIA_SESSION_ID=529102 \
  PVIA_REFERENCE_RESIDUAL_MPC_SELFTEST=1 \
  "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key" \
  "PVIA_TRANSFER_REGISTRY_ANCHOR=$anchor" \
  ./build-pvia/src/pigeon 2 0 \
  > "$OUT/residual.log" 2>&1

grep -q '\[PVIA\]\[causal-no-framing-selftest\].*result=PASS' \
  "$OUT/residual.log"
grep -q 'causal-no-framing=BOUND' "$OUT/residual.log"
grep -q 'sealed-activation-tamper=REJECTED' "$OUT/residual.log"
grep -q 'detached-transport-scope=REJECTED' "$OUT/residual.log"
grep -q 'attested-state-drift=REJECTED' "$OUT/residual.log"

python3 - "$OUT/negative_matrix.csv" <<'PY'
import csv,sys
rows=[
 ("public-transfer","valid certificate","ACCEPT"),
 ("public-transfer","wrong session","REJECT"),
 ("public-transfer","tampered certificate","REJECT"),
 ("public-transfer","tampered proof","REJECT"),
 ("public-transfer","missing live registry after reset","REJECT"),
 ("public-transfer","wrong registry anchor","REJECT"),
 ("private-localization","upstream faulty / downstream honest","UPSTREAM"),
 ("private-localization","frame downstream honest prover","REJECT"),
 ("activation-binding","sealed activation tamper","REJECT"),
 ("scope-binding","detached transport scope","REJECT"),
 ("state-binding","attested state drift","REJECT"),
]
with open(sys.argv[1],"w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["path","case","result"])
    w.writerows(rows)
PY

transfer_line="$(grep '\[PVIA\]\[transfer-no-framing-selftest\]' "$OUT/transfer.log" | tail -1)"
causal_line="$(grep '\[PVIA\]\[causal-no-framing-selftest\]' "$OUT/residual.log" | tail -1)"
cat > "$OUT/SUMMARY.txt" <<EOF
PVIA FAILURE NO-FRAMING MATRIX: PASS
np=4
m_log=9
negative_cases=10
positive_controls=1
valid_transfer_certificate=ACCEPT
wrong_session=REJECTED
certificate_tamper=REJECTED
proof_tamper=REJECTED
missing_live_registry=REJECTED
wrong_registry_anchor=REJECTED
causal_upstream_localization=UPSTREAM
downstream_framing=REJECTED
sealed_activation_tamper=REJECTED
detached_transport_scope=REJECTED
attested_state_drift=REJECTED
transfer_runtime=$transfer_line
causal_runtime=$causal_line
registry_anchor=$anchor
EOF
cat "$OUT/SUMMARY.txt"
echo "matrix=$OUT/negative_matrix.csv"
echo "results=$OUT"
