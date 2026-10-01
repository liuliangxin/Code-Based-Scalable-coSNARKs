#!/usr/bin/env bash
set -euo pipefail
ROOT="${ROOT:-/home/liuliangxin/Code-Based-Scalable-coSNARKs-main}"
REPEATS="${REPEATS:-5}"
WARMUP="${WARMUP:-1}"
Q="${Q:-32}"
PARTIES="${PARTIES:-4 8 16}"
BUILD="${BUILD:-0}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/experiments/results/localization_party_scaling_$STAMP}"
mkdir -p "$OUT"
cd "$ROOT"

first=1
for np in $PARTIES; do
  case_build=0
  if [[ "$BUILD" == "1" && "$first" == "1" ]]; then case_build=1; fi
  first=0
  NP="$np" BUILD="$case_build" REPEATS="$REPEATS" WARMUP="$WARMUP" \
    Q_SIZES="$Q" OUT="$OUT/np$np" \
    bash experiments/run_localization_scaling_xfusion.sh \
    > "$OUT/np${np}_runner.log" 2>&1
  grep -q '^PVIA LOCALIZATION SCALING: PASS' "$OUT/np$np/SUMMARY.txt"
  grep -q "^np=$np$" "$OUT/np$np/SUMMARY.txt"
done

python3 - "$OUT" "$Q" "$REPEATS" "$WARMUP" $PARTIES <<'PY'
import csv,sys
from pathlib import Path
out=Path(sys.argv[1]); q=int(sys.argv[2])
repeats=sys.argv[3]; warmup=sys.argv[4]
parties=[int(x) for x in sys.argv[5:]]
fields=['parties','q','fault','depth','subset_checks',
        'batch_mean_ms','batch_p95_ms','dispute_mean_ms','dispute_p95_ms',
        'dispute_auth_sent_kb']
rows=[]
for np in parties:
    stats=list(csv.DictReader((out/f'np{np}'/'summary_stats.csv').open(newline='')))
    def stat(fault,metric,key='mean'):
        for r in stats:
            if int(r['q'])==q and r['fault']==fault and r['metric']==metric:
                return float(r[key])
        raise KeyError((np,fault,metric,key))
    for fault in ['first','last']:
        rows.append({
          'parties':np,'q':q,'fault':fault,
          'depth':f'{stat(fault,"depth"):.0f}',
          'subset_checks':f'{stat(fault,"subset_checks"):.0f}',
          'batch_mean_ms':f'{stat(fault,"batch_ns")/1e6:.6f}',
          'batch_p95_ms':f'{stat(fault,"batch_ns","p95")/1e6:.6f}',
          'dispute_mean_ms':f'{stat(fault,"dispute_ns")/1e6:.6f}',
          'dispute_p95_ms':f'{stat(fault,"dispute_ns","p95")/1e6:.6f}',
          'dispute_auth_sent_kb':f'{stat(fault,"dispute_auth_sent_bytes")/1024:.3f}',
        })
with (out/'party_scaling.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
lines=[
 'PVIA LOCALIZATION PARTY SCALING: PASS',
 f'q={q}', f'repeats={repeats}', f'warmup={warmup}',
 'parties='+','.join(map(str,parties)),
 'fault_positions=first,last',
]
for row in rows:
    prefix=f"n{row['parties']}_{row['fault']}"
    for k in ['depth','subset_checks','batch_mean_ms','batch_p95_ms',
              'dispute_mean_ms','dispute_p95_ms','dispute_auth_sent_kb']:
        lines.append(f'{prefix}_{k}={row[k]}')
(out/'SUMMARY.txt').write_text('\n'.join(lines)+'\n')
print('\n'.join(lines))
PY

echo "csv=$OUT/party_scaling.csv"
echo "results=$OUT"
