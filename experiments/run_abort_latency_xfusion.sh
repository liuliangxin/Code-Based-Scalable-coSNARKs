#!/usr/bin/env bash
set -euo pipefail
export OMPI_MCA_btl=^openib

ROOT="${ROOT:-/home/liuliangxin/Code-Based-Scalable-coSNARKs-main}"
NP="${NP:-4}"
REPEATS="${REPEATS:-10}"
WARMUP="${WARMUP:-1}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/experiments/results/abort_latency_$STAMP}"
TMP="$(mktemp -d /tmp/pvia-abort-latency.XXXXXX)"
mkdir -p "$OUT"; chmod 700 "$TMP"
trap 'rm -rf -- "$TMP"' EXIT

if [[ "$NP" != "4" ]]; then
  echo "abort latency runner currently pins verified NP=4" >&2
  exit 2
fi
for r in 0 1 2 3; do
  umask 077
  openssl rand -hex 32 > "$TMP/rank_${r}.key"
done
cd "$ROOT"
cmake --build build-pvia -j2 > "$OUT/build.log" 2>&1

ANCHOR_PROBE="$OUT/anchor_probe.log"
mpirun -np 4 env PVIA_ENABLE=1 PVIA_SESSION_ID=428000 \
  "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key" \
  ./build-pvia/src/pigeon 2 0 > "$ANCHOR_PROBE" 2>&1
anchor="$(grep -oE 'transfer key registry commitment=[0-9a-f]{64}' "$ANCHOR_PROBE" | head -1 | cut -d= -f2)"
[[ "$anchor" =~ ^[0-9a-f]{64}$ ]] || exit 3
printf '%s\n' "$anchor" > "$OUT/registry_anchor.txt"

RAW="$OUT/raw_runs.csv"
python3 - "$RAW" <<'PY'
import csv,sys
fields=['scenario','iteration','max_failure_total_ns','mean_failure_total_ns',
        'max_scope_sync_ns','max_batch_check_ns','max_termination_query_ns',
        'max_cert_fetch_ns','max_cert_verify_ns','max_cert_encode_ns',
        'max_program_total_ns','sum_failure_handling_calls',
        'sum_public_abort_events','sum_unattributable_abort_events',
        'sum_cert_canonical_bytes','sum_auth_sent_bytes','sum_auth_recv_bytes']
with open(sys.argv[1],'w',newline='') as f:
    csv.DictWriter(f,fieldnames=fields).writeheader()
PY

append_case() {
  local scenario="$1" iteration="$2" aggregate="$3"
  python3 - "$RAW" "$scenario" "$iteration" "$aggregate" "$NP" <<'PY'
import csv,sys
raw,scenario,iteration,aggregate,np=sys.argv[1:]
with open(aggregate,newline='') as f: m=next(csv.DictReader(f))
np=int(np)
if int(m['sum_failure_handling_calls']) != np:
    raise SystemExit('expected exactly one failure handling call per rank')
if scenario == 'attached-public':
    if int(m['sum_public_abort_events']) != np or int(m['sum_unattributable_abort_events']) != 0:
        raise SystemExit('public-abort event counters mismatch')
    if int(m['sum_cert_canonical_bytes']) <= 0 or int(m['max_cert_verify_ns']) <= 0:
        raise SystemExit('public-abort certificate metrics missing')
else:
    if int(m['sum_public_abort_events']) != 0 or int(m['sum_unattributable_abort_events']) != np:
        raise SystemExit('replay-abort event counters mismatch')
    if int(m['sum_cert_canonical_bytes']) != 0 or int(m['max_cert_verify_ns']) != 0:
        raise SystemExit('replay path must not produce/verify a certificate')
fields=['scenario','iteration','max_failure_total_ns','mean_failure_total_ns',
        'max_scope_sync_ns','max_batch_check_ns','max_termination_query_ns',
        'max_cert_fetch_ns','max_cert_verify_ns','max_cert_encode_ns',
        'max_program_total_ns','sum_failure_handling_calls',
        'sum_public_abort_events','sum_unattributable_abort_events',
        'sum_cert_canonical_bytes','sum_auth_sent_bytes','sum_auth_recv_bytes']
out={'scenario':scenario,'iteration':iteration}
for field in fields[2:]: out[field]=m[field]
with open(raw,'a',newline='') as f:
    csv.DictWriter(f,fieldnames=fields).writerow(out)
PY
}

run_case() {
  local scenario="$1" tag="$2" session="$3" save="$4"
  local dir="$OUT/${scenario}_${tag}"; mkdir -p "$dir/metrics"
  mpirun -np 4 env PVIA_ENABLE=1 \
    "PVIA_SESSION_ID=$session" \
    "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key" \
    "PVIA_TRANSFER_REGISTRY_ANCHOR=$anchor" \
    PVIA_ROBUST_TERMINATION_RUNTIME_SELFTEST=1 \
    "PVIA_ROBUST_TERMINATION_RUNTIME_SELFTEST_MODE=$scenario" \
    PVIA_EXPERIMENT_METRICS=1 "PVIA_EXPERIMENT_LABEL=$scenario" \
    "PVIA_EXPERIMENT_METRICS_DIR=$dir/metrics" \
    ./build-pvia/src/pigeon 2 0 > "$dir/run.log" 2>&1
  grep -q "\[PVIA\]\[robust-termination-runtime-benchmark\] mode=$scenario result=PASS" "$dir/run.log"
  python3 experiments/aggregate_pvia_metrics.py "$dir/metrics" \
    --output "$dir/aggregate.csv" > "$dir/aggregate.log"
  if [[ "$save" == "1" ]]; then append_case "$scenario" "$tag" "$dir/aggregate.csv"; fi
}

for ((i=1;i<=WARMUP;i++)); do
  run_case attached-public "warmup_$i" $((428100+i)) 0
  run_case attached-replay "warmup_$i" $((428200+i)) 0
done
for ((i=1;i<=REPEATS;i++)); do
  if (( i % 2 == 1 )); then
    run_case attached-public "$i" $((428300+i)) 1
    run_case attached-replay "$i" $((428400+i)) 1
  else
    run_case attached-replay "$i" $((428400+i)) 1
    run_case attached-public "$i" $((428300+i)) 1
  fi
done

python3 experiments/summarize_repeated_metrics.py \
  "$RAW" "$OUT/summary_stats.csv" > "$OUT/summary.log"
python3 - "$OUT/summary_stats.csv" "$OUT/SUMMARY.txt" "$REPEATS" "$WARMUP" <<'PY'
import csv,sys
summary,out,repeats,warmup=sys.argv[1:]
with open(summary,newline='') as f: rows=list(csv.DictReader(f))
def stat(sc,metric,key='mean'):
    for r in rows:
        if r['scenario']==sc and r['metric']==metric: return float(r[key])
    raise KeyError((sc,metric,key))
lines=['PVIA ABORT LATENCY: PASS',f'repeats={repeats}',f'warmup={warmup}']
for sc in ['attached-public','attached-replay']:
    prefix='public' if sc=='attached-public' else 'replay'
    for key in ['mean','median','p95','stddev']:
        lines.append(f'{prefix}_failure_{key}_ms={stat(sc,"max_failure_total_ns",key)/1e6:.6f}')
    lines += [
      f'{prefix}_scope_sync_mean_ms={stat(sc,"max_scope_sync_ns")/1e6:.6f}',
      f'{prefix}_batch_check_mean_ms={stat(sc,"max_batch_check_ns")/1e6:.6f}',
      f'{prefix}_termination_query_mean_ms={stat(sc,"max_termination_query_ns")/1e6:.6f}',
      f'{prefix}_cert_verify_mean_ms={stat(sc,"max_cert_verify_ns")/1e6:.6f}',
      f'{prefix}_cert_bytes={stat(sc,"sum_cert_canonical_bytes"):.0f}']
open(out,'w').write('\n'.join(lines)+'\n')
PY
cat "$OUT/SUMMARY.txt"
echo "raw=$RAW"
echo "summary=$OUT/summary_stats.csv"
echo "results=$OUT"
