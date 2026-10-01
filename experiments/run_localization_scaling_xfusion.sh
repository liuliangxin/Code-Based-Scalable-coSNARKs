#!/usr/bin/env bash
set -euo pipefail
export OMPI_MCA_btl=^openib

ROOT="${ROOT:-/home/liuliangxin/Code-Based-Scalable-coSNARKs-main}"
NP="${NP:-4}"
REPEATS="${REPEATS:-10}"
WARMUP="${WARMUP:-2}"
Q_SIZES="${Q_SIZES:-4 8 16 32 64}"
BUILD="${BUILD:-0}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/experiments/results/localization_scaling_$STAMP}"
TMP="$(mktemp -d /tmp/pvia-localization-scaling.XXXXXX)"
mkdir -p "$OUT"

cd "$ROOT"
case "$BUILD" in
  1) cmake --build build-pvia -j2 > "$OUT/build.log" 2>&1 ;;
  0) printf 'build skipped by caller\n' > "$OUT/build.log" ;;
  *) echo "BUILD must be 0 or 1" >&2; exit 2 ;;
esac

for ((r=0;r<NP;r++)); do
  umask 077
  openssl rand -hex 32 > "$TMP/rank_${r}.key"
done

mpirun -np "$NP" env PVIA_ENABLE=1 PVIA_SESSION_ID=531000 \
  "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key" \
  ./build-pvia/src/pigeon 2 0 > "$OUT/anchor_probe.log" 2>&1
anchor="$(grep -oE 'transfer key registry commitment=[0-9a-f]{64}' \
  "$OUT/anchor_probe.log" | head -1 | cut -d= -f2)"
[[ "$anchor" =~ ^[0-9a-f]{64}$ ]] || exit 3
printf '%s\n' "$anchor" > "$OUT/registry_anchor.txt"

RAW="$OUT/raw_runs.csv"
printf '%s\n' 'q,fault,iteration,depth,subset_checks,batch_ns,dispute_ns,batch_auth_sent_bytes,dispute_auth_sent_bytes,batch_control_sent_bytes,dispute_control_sent_bytes,accused_owner,accused_object' > "$RAW"

run_one() {
  local q="$1" fault="$2" iteration="$3" save="$4" sid="$5"
  local log="$OUT/q${q}_${fault}_${iteration}.log"
  mpirun -np "$NP" env PVIA_ENABLE=1 \
    "PVIA_SESSION_ID=$sid" \
    PVIA_EXPERIMENT_METRICS=1 \
    "PVIA_LOCALIZATION_SCALING_Q=$q" \
    "PVIA_LOCALIZATION_SCALING_FAULT=$fault" \
    "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key" \
    "PVIA_TRANSFER_REGISTRY_ANCHOR=$anchor" \
    ./build-pvia/src/pigeon 2 0 > "$log" 2>&1
  local line
  line="$(grep '\[PVIA\]\[localization-scaling\]' "$log" | tail -1)"
  [[ "$line" == *"result=PASS"* ]] || exit 4
  python3 - "$RAW" "$q" "$fault" "$iteration" "$save" "$line" <<'PY'
import csv, math, re, sys
raw,q,fault,it,save,line=sys.argv[1:]
m=re.search(
 r'q=(\d+) fault=(first|last) depth=(\d+) subset_checks=(\d+) '
 r'batch_ns=(\d+) dispute_ns=(\d+) '
 r'batch_auth_sent_bytes=(\d+) dispute_auth_sent_bytes=(\d+) '
 r'batch_control_sent_bytes=(\d+) dispute_control_sent_bytes=(\d+) '
 r'accused_owner=(\d+) accused_object=(\d+) '
 r'counters_agree=(yes|no) result=(PASS|FAIL)', line)
if not m:
    raise SystemExit("failed to parse localization line")
keys=['q','fault','depth','subset_checks','batch_ns','dispute_ns',
      'batch_auth_sent_bytes','dispute_auth_sent_bytes',
      'batch_control_sent_bytes','dispute_control_sent_bytes',
      'accused_owner','accused_object','counters_agree','result']
d=dict(zip(keys,m.groups()))
qv=int(q)
expected_depth=int(math.log2(qv))
if 2**expected_depth != qv:
    raise SystemExit("q must be a power of two")
if int(d['depth']) != expected_depth:
    raise SystemExit(
        f"depth mismatch q={q}: {d['depth']} vs {expected_depth}")
expected_checks=expected_depth if fault=='first' else 2*expected_depth
if int(d['subset_checks']) != expected_checks:
    raise SystemExit(
        f"subset-check mismatch q={q} fault={fault}: "
        f"{d['subset_checks']} vs {expected_checks}")
if d['counters_agree']!='yes' or d['result']!='PASS':
    raise SystemExit("localization counters/result failed")
if save == '1':
    fields=['q','fault','iteration','depth','subset_checks','batch_ns',
            'dispute_ns','batch_auth_sent_bytes','dispute_auth_sent_bytes',
            'batch_control_sent_bytes','dispute_control_sent_bytes',
            'accused_owner','accused_object']
    row={k:d[k] for k in fields if k in d}
    row['q']=q
    row['fault']=fault
    row['iteration']=it
    with open(raw,'a',newline='') as f:
        csv.DictWriter(f,fieldnames=fields).writerow(row)
PY
}

session=531100
for q in $Q_SIZES; do
  for ((i=1;i<=WARMUP;i++)); do
    for fault in first last; do
      session=$((session+1))
      run_one "$q" "$fault" "warmup_$i" 0 "$session"
    done
  done
  for ((i=1;i<=REPEATS;i++)); do
    if (( i % 2 == 1 )); then faults="first last"; else faults="last first"; fi
    for fault in $faults; do
      session=$((session+1))
      run_one "$q" "$fault" "$i" 1 "$session"
    done
  done
done

python3 - "$RAW" "$OUT/summary_stats.csv" "$OUT/SUMMARY.txt" \
  "$REPEATS" "$WARMUP" "$NP" <<'PY'
import csv, math, statistics, sys
raw,summary_path,summary_txt,repeats,warmup,np=sys.argv[1:]
rows=list(csv.DictReader(open(raw,newline='')))
metrics=[
 'batch_ns','dispute_ns','batch_auth_sent_bytes',
 'dispute_auth_sent_bytes','subset_checks','depth']
def percentile(xs,p):
    xs=sorted(xs)
    if len(xs)==1: return xs[0]
    x=(len(xs)-1)*p
    lo=int(math.floor(x)); hi=int(math.ceil(x))
    if lo==hi: return xs[lo]
    return xs[lo]*(hi-x)+xs[hi]*(x-lo)
out=[]
groups={}
for r in rows:
    groups.setdefault((int(r['q']),r['fault']),[]).append(r)
for (q,fault),rs in sorted(groups.items()):
    for metric in metrics:
        xs=[float(r[metric]) for r in rs]
        out.append({
          'q':q,'fault':fault,'metric':metric,
          'mean':statistics.mean(xs),
          'median':statistics.median(xs),
          'p95':percentile(xs,.95),
          'stddev':statistics.stdev(xs) if len(xs)>1 else 0.0})
with open(summary_path,'w',newline='') as f:
    fields=['q','fault','metric','mean','median','p95','stddev']
    w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(out)

def stat(q,fault,metric,key='mean'):
    for r in out:
        if r['q']==q and r['fault']==fault and r['metric']==metric:
            return r[key]
    raise KeyError((q,fault,metric,key))
qs=sorted({q for q,_ in groups})
lines=[
 'PVIA LOCALIZATION SCALING: PASS',
 f'repeats={repeats}', f'warmup={warmup}',
 f'np={np}',
 'q_sizes=' + ','.join(map(str,qs)),
 'fault_positions=first,last',
 'complexity_scope=recursive-depth-and-subset-checks',
]
for q in qs:
    for fault in ['first','last']:
        prefix=f'q{q}_{fault}'
        lines += [
          f'{prefix}_depth={stat(q,fault,"depth"):.0f}',
          f'{prefix}_subset_checks={stat(q,fault,"subset_checks"):.0f}',
          f'{prefix}_batch_mean_ms={stat(q,fault,"batch_ns")/1e6:.6f}',
          f'{prefix}_batch_p95_ms={stat(q,fault,"batch_ns","p95")/1e6:.6f}',
          f'{prefix}_dispute_mean_ms={stat(q,fault,"dispute_ns")/1e6:.6f}',
          f'{prefix}_dispute_p95_ms={stat(q,fault,"dispute_ns","p95")/1e6:.6f}',
          f'{prefix}_dispute_auth_sent_kb={stat(q,fault,"dispute_auth_sent_bytes")/1024:.3f}',
        ]
open(summary_txt,'w').write('\n'.join(lines)+'\n')
print('\n'.join(lines))
PY

echo "raw=$RAW"
echo "stats=$OUT/summary_stats.csv"
echo "results=$OUT"
