#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-/home/liuliangxin/Code-Based-Scalable-coSNARKs-main}"
REPEATS="${REPEATS:-5}"
WARMUP="${WARMUP:-1}"
PARTIES="${PARTIES:-4 8 16 32}"
BUILD="${BUILD:-0}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/experiments/results/pappas_aligned_accountability_$STAMP}"

mkdir -p "$OUT"
cd "$ROOT"

first=1
for np in $PARTIES; do
  case_build=0
  if [[ "$BUILD" == "1" && "$first" == "1" ]]; then
    case_build=1
  fi
  first=0
  NP="$np" BUILD="$case_build" REPEATS="$REPEATS" WARMUP="$WARMUP" \
    M_LOG=18 SUMCHECK_LOG=14 PC_LOG=15 MULTREE_LOG=10 \
    OUT="$OUT/n$np" \
    bash experiments/run_copiop_overhead_xfusion.sh \
    > "$OUT/n${np}_runner.log" 2>&1
  grep -q '^PVIA coPIOP OVERHEAD: PASS' "$OUT/n$np/SUMMARY.txt"
done

python3 - "$OUT" "$REPEATS" "$WARMUP" $PARTIES <<'PY'
import csv,sys
from pathlib import Path
out=Path(sys.argv[1]); repeats=sys.argv[2]; warmup=sys.argv[3]
parties=[int(x) for x in sys.argv[4:]]
fields=[
  'parties','repeats','warmup',
  'baseline_total_ms','pvia_total_ms','total_median_overhead_pct',
  'baseline_peak_rss_mib','pvia_peak_rss_mib','peak_rss_median_overhead_pct',
  'baseline_rank0_ms','pvia_rank0_ms','rank0_median_overhead_pct',
  'baseline_reported_comm_mb','pvia_online_accounted_comm_mb',
  'online_comm_factor','pvia_total_accounted_comm_mb','total_comm_factor',
  'proof_kb','verifier_ms'
]
rows=[]
def kv(path):
    d={}
    for line in path.read_text().splitlines():
        if '=' in line:
            k,v=line.split('=',1); d[k]=v
    return d
for np in parties:
    s=kv(out/f'n{np}'/'SUMMARY.txt')
    base=float(s['disabled_reported_comm_mean_mb'])
    online=float(s['enabled_online_accounted_comm_mean_mb'])
    total=float(s['enabled_accounted_comm_mean_mb'])
    raw=list(csv.DictReader((out/f'n{np}'/'raw_runs.csv').open(newline='')))
    er=[r for r in raw if r['scenario']=='enabled']
    proof=sum(float(r['proof_kb']) for r in er)/len(er)
    verifier=1000*sum(float(r['verifier_total_s']) for r in er)/len(er)
    rows.append({
      'parties':np,'repeats':repeats,'warmup':warmup,
      'baseline_total_ms':f"{float(s['disabled_program_total_mean_ms']):.6f}",
      'pvia_total_ms':f"{float(s['enabled_program_total_mean_ms']):.6f}",
      'total_median_overhead_pct':f"{float(s['paired_program_overhead_median_pct']):.6f}",
      'baseline_peak_rss_mib':f"{float(s['disabled_peak_rss_max_mean_mib']):.6f}",
      'pvia_peak_rss_mib':f"{float(s['enabled_peak_rss_max_mean_mib']):.6f}",
      'peak_rss_median_overhead_pct':f"{float(s['paired_peak_rss_overhead_median_pct']):.6f}",
      'baseline_rank0_ms':f"{1000*float(s['disabled_rank0_pt_mean_s']):.6f}",
      'pvia_rank0_ms':f"{1000*float(s['enabled_rank0_pt_mean_s']):.6f}",
      'rank0_median_overhead_pct':f"{float(s['paired_rank0_pt_overhead_median_pct']):.6f}",
      'baseline_reported_comm_mb':f"{base:.6f}",
      'pvia_online_accounted_comm_mb':f"{online:.6f}",
      'online_comm_factor':f"{online/base:.6f}",
      'pvia_total_accounted_comm_mb':f"{total:.6f}",
      'total_comm_factor':f"{total/base:.6f}",
      'proof_kb':f"{proof:.6f}",
      'verifier_ms':f"{verifier:.6f}",
    })
with (out/'pappas_aligned_accountability.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)

md=[
 '# Pappas-aligned accountability overhead',
 '',
 'Uses the parameter shape preserved in the original repository test.sh: '
 'M_LOG=18, SUMCHECK_LOG=14, PC_LOG=15, MULTREE_LOG=10. '
 'Runs are local single-host MPI and therefore measure paired accountability '
 'overhead, not a reproduction of the original paper LAN/WAN absolute timings.',
 '',
 '| N | Baseline total ms | PVIA total ms | Total overhead | '
 'RSS base MiB | RSS PVIA MiB | RSS overhead | '
 'Baseline rank0 ms | PVIA rank0 ms | Rank0 overhead | '
 'Baseline comm MB | Online PVIA MB | Online factor | Total PVIA MB | Total factor |',
 '|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|',
]
for r in rows:
    md.append(
      f"| {r['parties']} | {float(r['baseline_total_ms']):.1f} | "
      f"{float(r['pvia_total_ms']):.1f} | {float(r['total_median_overhead_pct']):.1f}% | "
      f"{float(r['baseline_peak_rss_mib']):.1f} | {float(r['pvia_peak_rss_mib']):.1f} | "
      f"{float(r['peak_rss_median_overhead_pct']):.1f}% | "
      f"{float(r['baseline_rank0_ms']):.1f} | {float(r['pvia_rank0_ms']):.1f} | "
      f"{float(r['rank0_median_overhead_pct']):.1f}% | "
      f"{float(r['baseline_reported_comm_mb']):.2f} | "
      f"{float(r['pvia_online_accounted_comm_mb']):.2f} | "
      f"{float(r['online_comm_factor']):.2f}x | "
      f"{float(r['pvia_total_accounted_comm_mb']):.2f} | "
      f"{float(r['total_comm_factor']):.2f}x |")
(out/'pappas_aligned_accountability.md').write_text('\n'.join(md)+'\n')

lines=[
 'PVIA PAPPAS-ALIGNED ACCOUNTABILITY: PASS',
 f'repeats={repeats}', f'warmup={warmup}',
 'parties='+','.join(map(str,parties)),
 'm_log=18','sumcheck_log=14','pc_log=15','multree_log=10',
 'environment=single-host-mpi',
 'claim_scope=paired-accountability-overhead-not-paper-lan-wan-reproduction',
]
for r in rows:
    n=r['parties']
    for k in [
      'total_median_overhead_pct','peak_rss_median_overhead_pct',
      'rank0_median_overhead_pct','online_comm_factor','total_comm_factor']:
        lines.append(f'n{n}_{k}={r[k]}')
(out/'SUMMARY.txt').write_text('\n'.join(lines)+'\n')
print('\n'.join(lines))
PY

echo "csv=$OUT/pappas_aligned_accountability.csv"
echo "results=$OUT"
