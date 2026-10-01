#!/usr/bin/env bash
set -euo pipefail
export OMPI_MCA_btl=^openib

ROOT="${ROOT:-/home/liuliangxin/Code-Based-Scalable-coSNARKs-main}"
BATCHES="${BATCHES:-10}"
INNER_REPEATS="${INNER_REPEATS:-1000}"
WARMUP="${WARMUP:-1}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/experiments/results/robust_abort_judge_$STAMP}"
TMP="$(mktemp -d /tmp/pvia-judge-bench.XXXXXX)"
mkdir -p "$OUT"; chmod 700 "$TMP"
trap 'rm -rf -- "$TMP"' EXIT

for r in 0 1 2 3; do
  umask 077
  openssl rand -hex 32 > "$TMP/rank_${r}.key"
done
cd "$ROOT"
cmake --build build-pvia -j2 > "$OUT/build.log" 2>&1

COMMON=(mpirun -np 4 env PVIA_ENABLE=1
  "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key")
"${COMMON[@]}" PVIA_SESSION_ID=427000 \
  PVIA_ROBUST_TERMINATION_RUNTIME_SELFTEST=1 \
  ./build-pvia/src/pigeon 2 0 > "$OUT/runtime_unanchored.log" 2>&1
anchor="$(grep -oE 'transfer key registry commitment=[0-9a-f]{64}' \
  "$OUT/runtime_unanchored.log" | head -1 | cut -d= -f2)"
[[ "$anchor" =~ ^[0-9a-f]{64}$ ]] || exit 3
printf '%s\n' "$anchor" > "$OUT/registry_anchor.txt"
cert="$OUT/runtime_robust_abort.cert"
"${COMMON[@]}" PVIA_SESSION_ID=427001 \
  PVIA_ROBUST_TERMINATION_RUNTIME_SELFTEST=1 \
  "PVIA_TRANSFER_REGISTRY_ANCHOR=$anchor" \
  "PVIA_ROBUST_ABORT_CERT_OUT=$cert" \
  ./build-pvia/src/pigeon 2 0 > "$OUT/runtime_anchored.log" 2>&1
grep -q '\[PVIA\]\[robust-termination-runtime-selftest\] PASS' \
  "$OUT/runtime_anchored.log"
test -s "$cert"

mpirun -np 1 ./build-pvia/src/pigeon \
  --pvia-robust-abort-judge "$cert" "$anchor" \
  > "$OUT/judge_accept.log" 2>&1
grep -q '\[PVIA\]\[robust-abort-judge\] ACCEPT' "$OUT/judge_accept.log"
if [[ "${anchor:0:1}" == "0" ]]; then
  wrong_anchor="1${anchor:1}"
else
  wrong_anchor="0${anchor:1}"
fi
set +e
mpirun -np 1 ./build-pvia/src/pigeon \
  --pvia-robust-abort-judge "$cert" "$wrong_anchor" \
  > "$OUT/judge_reject.log" 2>&1
reject_rc=$?
set -e
[[ "$reject_rc" == "8" ]] || exit 4
grep -q '\[PVIA\]\[robust-abort-judge\] REJECT' "$OUT/judge_reject.log"
RAW="$OUT/raw_runs.csv"
python3 - "$RAW" <<'PY'
import csv,sys
fields=['scenario','iteration','repeats','completed','total_ns','mean_ns',
        'canonical_bytes','serialized_file_bytes']
with open(sys.argv[1],'w',newline='') as f:
    csv.DictWriter(f,fieldnames=fields).writeheader()
PY
serialized_bytes="$(wc -c < "$cert")"

run_batch() {
  local tag="$1" save="$2"
  local log="$OUT/judge_benchmark_${tag}.log"
  PVIA_ROBUST_ABORT_JUDGE_BENCHMARK_REPEATS="$INNER_REPEATS" \
    mpirun -np 1 ./build-pvia/src/pigeon \
    --pvia-robust-abort-judge "$cert" "$anchor" > "$log" 2>&1
  grep -q '\[PVIA\]\[robust-abort-judge\] ACCEPT' "$log"
  local line
  line="$(grep '\[PVIA\]\[robust-abort-judge-benchmark\]' "$log" | tail -1)"
  [[ -n "$line" ]] || exit 5
  if [[ "$save" == "1" ]]; then
    python3 - "$RAW" "$tag" "$serialized_bytes" "$line" <<'PY'
import csv,re,sys
raw,tag,file_bytes,line=sys.argv[1:]
m=re.search(r'repeats=(\d+) completed=(\d+) total_ns=(\d+) mean_ns=(\d+) canonical_bytes=(\d+)',line)
if not m: raise SystemExit('failed to parse judge benchmark line')
row={'scenario':'robust_abort_judge','iteration':tag,'repeats':m.group(1),
     'completed':m.group(2),'total_ns':m.group(3),'mean_ns':m.group(4),
     'canonical_bytes':m.group(5),'serialized_file_bytes':file_bytes}
with open(raw,newline='') as f: fields=next(csv.reader(f))
with open(raw,'a',newline='') as f:
    csv.DictWriter(f,fieldnames=fields).writerow(row)
PY
  fi
}
for ((i=1;i<=WARMUP;i++)); do
  run_batch "warmup_$i" 0
done
for ((i=1;i<=BATCHES;i++)); do
  run_batch "$i" 1
done

python3 experiments/summarize_repeated_metrics.py \
  "$RAW" "$OUT/summary_stats.csv" > "$OUT/summary.log"
python3 - "$OUT/summary_stats.csv" "$OUT/SUMMARY.txt" \
  "$BATCHES" "$WARMUP" "$INNER_REPEATS" <<'PY'
import csv,sys
summary,out,batches,warmup,inner=sys.argv[1:]
with open(summary,newline='') as f: rows=list(csv.DictReader(f))
def stat(metric,key):
    for r in rows:
        if r['scenario']=='robust_abort_judge' and r['metric']==metric:
            return float(r[key])
    raise KeyError((metric,key))
lines=[
 'PVIA ROBUST ABORT JUDGE BENCHMARK: PASS',
 f'batches={batches}', f'warmup={warmup}', f'inner_repeats={inner}',
 f'mean_verify_ms={stat("mean_ns","mean")/1e6:.6f}',
 f'median_verify_ms={stat("mean_ns","median")/1e6:.6f}',
 f'p95_verify_ms={stat("mean_ns","p95")/1e6:.6f}',
 f'stddev_verify_ms={stat("mean_ns","stddev")/1e6:.6f}',
 f'canonical_certificate_bytes={stat("canonical_bytes","mean"):.0f}',
 f'serialized_certificate_bytes={stat("serialized_file_bytes","mean"):.0f}',
 'correct_anchor=ACCEPT', 'wrong_anchor=REJECT_RC8']
open(out,'w').write('\n'.join(lines)+'\n')
PY
cat "$OUT/SUMMARY.txt"
echo "raw=$RAW"
echo "summary=$OUT/summary_stats.csv"
echo "results=$OUT"
