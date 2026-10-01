#!/usr/bin/env bash
set -euo pipefail
export OMPI_MCA_btl=^openib

ROOT="${ROOT:-/home/liuliangxin/Code-Based-Scalable-coSNARKs-main}"
NP="${NP:-4}"
REPEATS="${REPEATS:-10}"
WARMUP="${WARMUP:-2}"
M_LOG="${M_LOG:-10}"
CIR="${CIR:-1}"
SUMCHECK_LOG="${SUMCHECK_LOG:-8}"
PC_LOG="${PC_LOG:-9}"
MULTREE_LOG="${MULTREE_LOG:-6}"
BUILD="${BUILD:-1}"
RESUME="${RESUME:-0}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/experiments/results/copiop_overhead_$STAMP}"
TMP="$(mktemp -d /tmp/pvia-copiop.XXXXXX)"
mkdir -p "$OUT"; chmod 700 "$TMP"
trap 'rm -rf -- "$TMP"' EXIT

if [[ "$NP" != "4" && "$NP" != "8" && "$NP" != "16" && "$NP" != "32" ]]; then
  echo "coPIOP overhead runner currently allows only verified NP=4, NP=8, NP=16, or NP=32" >&2
  exit 2
fi
for ((r=0;r<NP;r++)); do
  umask 077
  openssl rand -hex 32 > "$TMP/rank_${r}.key"
done
cd "$ROOT"
case "$BUILD" in
  1) cmake --build build-pvia -j2 > "$OUT/build.log" 2>&1 ;;
  0) printf 'build skipped by caller; preflight build already completed\n' > "$OUT/build.log" ;;
  *) echo "BUILD must be 0 or 1" >&2; exit 2 ;;
esac
ANCHOR_PROBE="$OUT/anchor_probe.log"
mpirun -np "$NP" env \
  -u PVIA_MC_PROVIDER_LIBRARY \
  -u PVIA_MC_PROVIDER_PROOF_SYSTEM_ID \
  PVIA_ENABLE=1 PVIA_SESSION_ID=426000 \
  "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key" \
  ./build-pvia/src/pigeon 2 0 > "$ANCHOR_PROBE" 2>&1
anchor="$(grep -oE 'transfer key registry commitment=[0-9a-f]{64}' \
  "$ANCHOR_PROBE" | head -1 | cut -d= -f2)"
[[ "$anchor" =~ ^[0-9a-f]{64}$ ]] || exit 3
printf '%s\n' "$anchor" > "$OUT/registry_anchor.txt"

RAW="$OUT/raw_runs.csv"
if [[ "$RESUME" != "1" || ! -s "$RAW" ]]; then
python3 - "$RAW" <<'PY'
import csv,sys
fields=['scenario','iteration','label','session_id','world_size','rank_rows',
       'mean_program_total_ns','max_program_total_ns',
       'mean_peak_rss_kb','max_peak_rss_kb',
       'rank0_pt_s','rank0_cpu_pt_s',
       'rank0_comp_s','verifier_total_s','proof_kb','reported_comm_mb',
       'interaction_rounds','sum_auth_sent_bytes','sum_auth_recv_bytes',
       'sum_auth_collective_calls',
       'sum_control_sent_bytes','sum_control_recv_bytes',
       'sum_control_sent_messages','sum_control_recv_messages',
       'control_collective_calls_per_rank','control_sent_recv_bytes_match',
       'control_sent_recv_messages_match',
       'sum_runtime_init_control_sent_bytes','sum_runtime_init_control_recv_bytes',
       'runtime_init_control_collective_calls_per_rank',
       'sum_preprocessing_control_sent_bytes','sum_preprocessing_control_recv_bytes',
       'preprocessing_control_collective_calls_per_rank',
       'sum_initial_validity_control_sent_bytes','sum_initial_validity_control_recv_bytes',
       'initial_validity_control_collective_calls_per_rank',
       'sum_initial_validity_runs','sum_initial_validity_strong_runs',
       'consistency_provider_present','consistency_provider_production_ready',
       'consistency_provider_acceptance_present','consistency_provider_protocol_id',
       'sum_consistency_provider_control_sent_bytes',
       'sum_consistency_provider_control_recv_bytes',
       'consistency_provider_control_collective_calls_per_rank',
       'unclassified_control_sent_bytes','unclassified_control_recv_bytes',
       'unclassified_control_collective_calls','control_scope_partition_complete',
       'sum_transfer_meta_recv_bytes','sum_transfer_meta_recv_messages',
       'sum_transfer_meta_seal_calls','sum_transfer_meta_observe_calls',
       'sum_transfer_meta_verify_calls',
       'sum_public_direct_validation_control_sent_bytes',
       'sum_public_direct_validation_control_recv_bytes',
       'public_direct_validation_control_collective_calls_per_rank',
       'max_transfer_meta_seal_ns',
       'max_transfer_meta_observe_ns','max_transfer_meta_verify_ns',
       'sent_recv_bytes_match','sent_recv_messages_match']
with open(sys.argv[1],'w',newline='') as f:
    csv.DictWriter(f,fieldnames=fields).writeheader()
PY
fi

append_case() {
  local scenario="$1" iteration="$2" aggregate="$3" log="$4"
  python3 - "$RAW" "$scenario" "$iteration" "$aggregate" "$log" <<'PY'
import csv,re,sys
raw,scenario,iteration,aggregate,log=sys.argv[1:]
with open(aggregate,newline='') as f: m=next(csv.DictReader(f))
txt=open(log,errors='replace').read()
rank0=re.search(r'Id\s*:\s*0, Pt:\s*([0-9.]+), CPU Only Pt:\s*([0-9.]+), Computation only:\s*([0-9.]+), Vt:\s*([0-9.]+)',txt)
ver=re.search(r'Vt\s*:\s*([0-9.]+) sec, Ps:\s*([0-9.]+) KB, Com:\s*([0-9.]+) MB',txt)
rounds=re.search(r'Interaction Rounds:\s*(\d+)',txt)
if not rank0 or not ver or not rounds or 'Error' in txt:
    raise SystemExit('failed to parse successful coPIOP run')
out={
 'scenario':scenario,'iteration':iteration,'label':m['label'],
 'session_id':m['session_id'],'world_size':m['world_size'],'rank_rows':m['rank_rows'],
 'mean_program_total_ns':m['mean_program_total_ns'],
 'max_program_total_ns':m['max_program_total_ns'],
 'mean_peak_rss_kb':m['mean_peak_rss_kb'],
 'max_peak_rss_kb':m['max_peak_rss_kb'],
 'rank0_pt_s':rank0.group(1),'rank0_cpu_pt_s':rank0.group(2),
 'rank0_comp_s':rank0.group(3),'verifier_total_s':ver.group(1),
 'proof_kb':ver.group(2),'reported_comm_mb':ver.group(3),
 'interaction_rounds':rounds.group(1),'sum_auth_sent_bytes':m['sum_auth_sent_bytes'],
 'sum_auth_recv_bytes':m['sum_auth_recv_bytes'],
 'sum_auth_collective_calls':m['sum_auth_collective_calls'],
 'sum_control_sent_bytes':m['sum_control_sent_bytes'],
 'sum_control_recv_bytes':m['sum_control_recv_bytes'],
 'sum_control_sent_messages':m['sum_control_sent_messages'],
 'sum_control_recv_messages':m['sum_control_recv_messages'],
 'control_collective_calls_per_rank':m['control_collective_calls_per_rank'],
 'control_sent_recv_bytes_match':m['control_sent_recv_bytes_match'],
 'control_sent_recv_messages_match':m['control_sent_recv_messages_match'],
 'sum_runtime_init_control_sent_bytes':m['sum_runtime_init_control_sent_bytes'],
 'sum_runtime_init_control_recv_bytes':m['sum_runtime_init_control_recv_bytes'],
 'runtime_init_control_collective_calls_per_rank':m['runtime_init_control_collective_calls_per_rank'],
 'sum_preprocessing_control_sent_bytes':m['sum_preprocessing_control_sent_bytes'],
 'sum_preprocessing_control_recv_bytes':m['sum_preprocessing_control_recv_bytes'],
 'preprocessing_control_collective_calls_per_rank':m['preprocessing_control_collective_calls_per_rank'],
 'sum_initial_validity_control_sent_bytes':m['sum_initial_validity_control_sent_bytes'],
 'sum_initial_validity_control_recv_bytes':m['sum_initial_validity_control_recv_bytes'],
 'initial_validity_control_collective_calls_per_rank':m['initial_validity_control_collective_calls_per_rank'],
 'sum_initial_validity_runs':m['sum_initial_validity_runs'],
 'sum_initial_validity_strong_runs':m['sum_initial_validity_strong_runs'],
 'consistency_provider_present':m['consistency_provider_present'],
 'consistency_provider_production_ready':m['consistency_provider_production_ready'],
 'consistency_provider_acceptance_present':m['consistency_provider_acceptance_present'],
 'consistency_provider_protocol_id':m['consistency_provider_protocol_id'],
 'sum_consistency_provider_control_sent_bytes':m['sum_consistency_provider_control_sent_bytes'],
 'sum_consistency_provider_control_recv_bytes':m['sum_consistency_provider_control_recv_bytes'],
 'consistency_provider_control_collective_calls_per_rank':m['consistency_provider_control_collective_calls_per_rank'],
 'unclassified_control_sent_bytes':m['unclassified_control_sent_bytes'],
 'unclassified_control_recv_bytes':m['unclassified_control_recv_bytes'],
 'unclassified_control_collective_calls':m['unclassified_control_collective_calls'],
 'control_scope_partition_complete':m['control_scope_partition_complete'],
 'sum_transfer_meta_recv_bytes':m['sum_transfer_meta_recv_bytes'],
 'sum_transfer_meta_recv_messages':m['sum_transfer_meta_recv_messages'],
 'sum_transfer_meta_seal_calls':m['sum_transfer_meta_seal_calls'],
 'sum_transfer_meta_observe_calls':m['sum_transfer_meta_observe_calls'],
 'sum_transfer_meta_verify_calls':m['sum_transfer_meta_verify_calls'],
 'sum_public_direct_validation_control_sent_bytes':m['sum_public_direct_validation_control_sent_bytes'],
 'sum_public_direct_validation_control_recv_bytes':m['sum_public_direct_validation_control_recv_bytes'],
 'public_direct_validation_control_collective_calls_per_rank':m['public_direct_validation_control_collective_calls_per_rank'],
 'max_transfer_meta_seal_ns':m['max_transfer_meta_seal_ns'],
 'max_transfer_meta_observe_ns':m['max_transfer_meta_observe_ns'],
 'max_transfer_meta_verify_ns':m['max_transfer_meta_verify_ns'],
 'sent_recv_bytes_match':m['sent_recv_bytes_match'],
 'sent_recv_messages_match':m['sent_recv_messages_match']}
with open(raw,newline='') as f:
    reader=csv.DictReader(f)
    fields=reader.fieldnames
    existing=list(reader)
existing=[
    r for r in existing
    if not (r.get('scenario')==scenario and r.get('iteration')==iteration)]
with open(raw,'w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields)
    w.writeheader()
    w.writerows(existing)
    w.writerow(out)
PY
}

run_case() {
  local scenario="$1" tag="$2" session="$3" save="$4"
  local dir="$OUT/${scenario}_${tag}"; mkdir -p "$dir/metrics"
  local envs=(PVIA_EXPERIMENT_METRICS=1 "PVIA_EXPERIMENT_LABEL=$scenario"
    "PVIA_EXPERIMENT_METRICS_DIR=$dir/metrics" "PVIA_SESSION_ID=$session")
  if [[ "$scenario" == "disabled" ]]; then
    envs+=(PVIA_ENABLE=0)
  else
    envs+=(PVIA_ENABLE=1
      "PVIA_TRANSFER_PRIVATE_KEY_FILE=$TMP/rank_{rank}.key"
      "PVIA_TRANSFER_REGISTRY_ANCHOR=$anchor")
  fi
  local metric_count
  metric_count="$(find "$dir/metrics" -maxdepth 1 -type f     -name 'pvia_metrics_rank_*.csv' | wc -l)"
  local reusable=0
  if [[ "$RESUME" == "1" && -f "$dir/run.log" &&
        "$metric_count" -eq "$NP" ]] &&
     grep -q 'Interaction Rounds:' "$dir/run.log"; then
    if [[ "$scenario" != "enabled" ]] ||
       grep -q 'anchored=yes' "$dir/run.log"; then
      reusable=1
    fi
  fi

  if [[ "$reusable" == "0" ]]; then
    if [[ "$scenario" == "disabled" ]]; then
      mpirun -np "$NP" env \
        -u PVIA_MC_PROVIDER_LIBRARY \
        -u PVIA_MC_PROVIDER_PROOF_SYSTEM_ID \
        "${envs[@]}" \
        ./build-pvia/src/pigeon \
        0 "$M_LOG" "$CIR" "$SUMCHECK_LOG" "$PC_LOG" "$MULTREE_LOG" \
        > "$dir/run.log" 2>&1
    else
      mpirun -np "$NP" env "${envs[@]}" \
        ./build-pvia/src/pigeon \
        0 "$M_LOG" "$CIR" "$SUMCHECK_LOG" "$PC_LOG" "$MULTREE_LOG" \
        > "$dir/run.log" 2>&1
    fi
  else
    printf 'reused completed case: %s_%s
' "$scenario" "$tag"       >> "$OUT/resume.log"
  fi

  grep -q 'Interaction Rounds:' "$dir/run.log"
  if [[ "$scenario" == "enabled" ]]; then
    grep -q 'anchored=yes' "$dir/run.log"
  fi
  python3 experiments/aggregate_pvia_metrics.py "$dir/metrics" \
    --output "$dir/aggregate.csv" > "$dir/aggregate.log"
  if [[ "$save" == "1" ]]; then
    append_case "$scenario" "$tag" "$dir/aggregate.csv" "$dir/run.log"
  fi
}

for ((i=1;i<=WARMUP;i++)); do
  run_case disabled "warmup_$i" $((426100+i)) 0
  run_case enabled "warmup_$i" $((426200+i)) 0
done

for ((i=1;i<=REPEATS;i++)); do
  if (( i % 2 == 1 )); then
    run_case disabled "$i" $((426300+i)) 1
    run_case enabled "$i" $((426400+i)) 1
  else
    run_case enabled "$i" $((426400+i)) 1
    run_case disabled "$i" $((426300+i)) 1
  fi
done

python3 experiments/summarize_repeated_metrics.py \
  "$RAW" "$OUT/summary_stats.csv" > "$OUT/summary.log"
python3 experiments/summarize_paired_overhead.py \
  "$RAW" "$OUT/paired_runs.csv" "$OUT/paired_summary.csv" > "$OUT/paired.log"
python3 - "$OUT/summary_stats.csv" "$OUT/paired_summary.csv" "$OUT/SUMMARY.txt" "$REPEATS" "$WARMUP" <<'PY'
import csv,sys
summary,paired_summary,out,repeats,warmup=sys.argv[1:]
with open(summary,newline='') as f: rows=list(csv.DictReader(f))
with open(paired_summary,newline='') as f: paired_rows=list(csv.DictReader(f))
def pstat(metric,key='mean'):
    for r in paired_rows:
        if r['metric']==metric: return float(r[key])
    raise KeyError((metric,key))
def mean(sc,metric):
    for r in rows:
        if r['scenario']==sc and r['metric']==metric:
            return float(r['mean'])
    raise KeyError((sc,metric))
d_total=mean('disabled','max_program_total_ns')
e_total=mean('enabled','max_program_total_ns')
d_peak=mean('disabled','max_peak_rss_kb')
e_peak=mean('enabled','max_peak_rss_kb')
d_pt=mean('disabled','rank0_pt_s'); e_pt=mean('enabled','rank0_pt_s')
d_comm=mean('disabled','reported_comm_mb'); e_comm=mean('enabled','reported_comm_mb')
d_meta=mean('disabled','sum_transfer_meta_recv_bytes')
e_meta=mean('enabled','sum_transfer_meta_recv_bytes')
e_meta_msgs=mean('enabled','sum_transfer_meta_recv_messages')
e_auth_sent=mean('enabled','sum_auth_sent_bytes')
e_auth_recv=mean('enabled','sum_auth_recv_bytes')
e_auth_collectives=mean('enabled','sum_auth_collective_calls')
e_auth_bytes_match=mean('enabled','sent_recv_bytes_match')
e_control_sent=mean('enabled','sum_control_sent_bytes')
e_control_recv=mean('enabled','sum_control_recv_bytes')
e_control_sent_msgs=mean('enabled','sum_control_sent_messages')
e_control_recv_msgs=mean('enabled','sum_control_recv_messages')
e_control_collectives=mean('enabled','control_collective_calls_per_rank')
e_control_bytes_match=mean('enabled','control_sent_recv_bytes_match')
e_control_messages_match=mean('enabled','control_sent_recv_messages_match')
e_runtime_init_control=mean('enabled','sum_runtime_init_control_sent_bytes')
e_preprocessing_control=mean('enabled','sum_preprocessing_control_sent_bytes')
e_validity_control=mean('enabled','sum_initial_validity_control_sent_bytes')
e_provider_control=mean('enabled','sum_consistency_provider_control_sent_bytes')
e_public_direct_control=mean('enabled','sum_public_direct_validation_control_sent_bytes')
e_runtime_init_collectives=mean('enabled','runtime_init_control_collective_calls_per_rank')
e_preprocessing_collectives=mean('enabled','preprocessing_control_collective_calls_per_rank')
e_validity_collectives=mean('enabled','initial_validity_control_collective_calls_per_rank')
e_provider_control_collectives=mean('enabled','consistency_provider_control_collective_calls_per_rank')
e_validity_runs=mean('enabled','sum_initial_validity_runs')
e_validity_strong_runs=mean('enabled','sum_initial_validity_strong_runs')
e_validity_strong_active=(
    1 if e_validity_runs > 0 and abs(e_validity_strong_runs-e_validity_runs) < 0.5
    else 0)
e_provider_present=mean('enabled','consistency_provider_present')
e_provider_ready=mean('enabled','consistency_provider_production_ready')
e_provider_acceptance=mean('enabled','consistency_provider_acceptance_present')
e_provider_protocol_id=mean('enabled','consistency_provider_protocol_id')
e_provider_active=(
    1 if e_provider_present > 0.5 and e_provider_ready > 0.5 and
    e_provider_acceptance > 0.5 and e_provider_protocol_id > 0.5 else 0)
e_public_direct_collectives=mean('enabled','public_direct_validation_control_collective_calls_per_rank')
e_unclassified_control=mean('enabled','unclassified_control_sent_bytes')
e_scope_partition_complete=mean('enabled','control_scope_partition_complete')
e_seal_calls=mean('enabled','sum_transfer_meta_seal_calls')
e_seal_ns=mean('enabled','max_transfer_meta_seal_ns')
e_observe_ns=mean('enabled','max_transfer_meta_observe_ns')
e_verify_ns=mean('enabled','max_transfer_meta_verify_ns')
def overhead(a,b): return (b/a-1.0)*100.0 if a else 0.0
lines=[
 'PVIA coPIOP OVERHEAD: PASS', f'repeats={repeats}', f'warmup={warmup}',
 f'disabled_program_total_mean_ms={d_total/1e6:.6f}',
 f'enabled_program_total_mean_ms={e_total/1e6:.6f}',
 f'program_total_overhead_pct={overhead(d_total,e_total):.3f}',
 f'disabled_peak_rss_max_mean_mib={d_peak/1024.0:.6f}',
 f'enabled_peak_rss_max_mean_mib={e_peak/1024.0:.6f}',
 f'peak_rss_overhead_pct={overhead(d_peak,e_peak):.3f}',
 f'disabled_rank0_pt_mean_s={d_pt:.6f}', f'enabled_rank0_pt_mean_s={e_pt:.6f}',
 f'rank0_pt_overhead_pct={overhead(d_pt,e_pt):.3f}',
 f'disabled_reported_comm_mean_mb={d_comm:.6f}',
 f'enabled_reported_comm_mean_mb={e_comm:.6f}',
 f'reported_comm_overhead_pct={overhead(d_comm,e_comm):.3f}',
 f'disabled_pvia_metadata_recv_mean_bytes={d_meta:.3f}',
 f'enabled_pvia_metadata_recv_mean_bytes={e_meta:.3f}',
 f'enabled_pvia_metadata_recv_mean_mib={e_meta/(1024.0*1024.0):.6f}',
 f'enabled_pvia_metadata_recv_mean_messages={e_meta_msgs:.3f}',
 f'enabled_authenticated_control_sent_mean_bytes={e_auth_sent:.3f}',
 f'enabled_authenticated_control_recv_mean_bytes={e_auth_recv:.3f}',
 f'enabled_authenticated_control_collective_sum_calls={e_auth_collectives:.3f}',
 f'enabled_authenticated_control_bytes_match={e_auth_bytes_match:.0f}',
 f'enabled_control_sent_mean_bytes={e_control_sent:.3f}',
 f'enabled_control_recv_mean_bytes={e_control_recv:.3f}',
 f'enabled_control_sent_mean_messages={e_control_sent_msgs:.3f}',
 f'enabled_control_recv_mean_messages={e_control_recv_msgs:.3f}',
 f'enabled_control_collectives_per_rank={e_control_collectives:.3f}',
 f'enabled_control_bytes_match={e_control_bytes_match:.0f}',
 f'enabled_control_messages_match={e_control_messages_match:.0f}',
 f'enabled_runtime_init_control_mean_bytes={e_runtime_init_control:.3f}',
 f'enabled_preprocessing_control_mean_bytes={e_preprocessing_control:.3f}',
 f'enabled_initial_validity_control_mean_bytes={e_validity_control:.3f}',
 f'enabled_consistency_provider_control_mean_bytes={e_provider_control:.3f}',
 f'enabled_public_direct_validation_control_mean_bytes={e_public_direct_control:.3f}',
 f'enabled_offline_control_mean_bytes={e_runtime_init_control + e_preprocessing_control:.3f}',
 f'enabled_runtime_init_control_collectives={e_runtime_init_collectives:.3f}',
 f'enabled_preprocessing_control_collectives={e_preprocessing_collectives:.3f}',
 f'enabled_initial_validity_control_collectives={e_validity_collectives:.3f}',
 f'enabled_consistency_provider_control_collectives={e_provider_control_collectives:.3f}',
 f'enabled_initial_validity_run_rank_count={e_validity_runs:.3f}',
 f'enabled_initial_validity_strong_run_rank_count={e_validity_strong_runs:.3f}',
 f'enabled_initial_validity_strong_active={e_validity_strong_active}',
 f'enabled_consistency_provider_present={e_provider_present:.0f}',
 f'enabled_consistency_provider_production_ready={e_provider_ready:.0f}',
 f'enabled_consistency_provider_acceptance_present={e_provider_acceptance:.0f}',
 f'enabled_consistency_provider_protocol_id={e_provider_protocol_id:.0f}',
 f'enabled_consistency_provider_active={e_provider_active}',
 f'enabled_public_direct_validation_control_collectives={e_public_direct_collectives:.3f}',
 f'enabled_unclassified_control_mean_bytes={e_unclassified_control:.3f}',
 f'enabled_control_scope_partition_complete={e_scope_partition_complete:.0f}',
 f'enabled_online_accounted_comm_mean_mb={e_comm + (e_auth_sent + e_provider_control + e_validity_control + e_public_direct_control + e_meta)/(1024.0*1024.0):.6f}',
 f'enabled_accounted_comm_mean_mb={e_comm + (e_auth_sent + e_control_sent + e_meta)/(1024.0*1024.0):.6f}',
 f'enabled_pvia_metadata_seal_mean_calls={e_seal_calls:.3f}',
 f'pvia_metadata_vs_reported_comm_pct={100.0*e_meta/(e_comm*1024.0*1024.0) if e_comm else 0.0:.3f}',
 f'control_vs_reported_comm_pct={100.0*e_control_sent/(e_comm*1024.0*1024.0) if e_comm else 0.0:.3f}',
 f'enabled_authenticated_control_vs_reported_comm_pct={100.0*e_auth_sent/(e_comm*1024.0*1024.0) if e_comm else 0.0:.3f}',
 f'enabled_transfer_meta_seal_maxrank_mean_ms={e_seal_ns/1e6:.6f}',
 f'enabled_transfer_meta_observe_maxrank_mean_ms={e_observe_ns/1e6:.6f}',
 f'enabled_transfer_meta_verify_maxrank_mean_ms={e_verify_ns/1e6:.6f}',
 f'transfer_meta_verify_vs_observe_pct={100.0*e_verify_ns/e_observe_ns if e_observe_ns else 0.0:.3f}',
 f'paired_program_overhead_mean_pct={pstat("program_total_ms_overhead_pct"):.3f}',
 f'paired_program_overhead_median_pct={pstat("program_total_ms_overhead_pct","median"):.3f}',
 f'paired_program_overhead_p95_pct={pstat("program_total_ms_overhead_pct","p95"):.3f}',
 f'paired_program_overhead_stddev_pct={pstat("program_total_ms_overhead_pct","stddev"):.3f}',
 f'paired_peak_rss_overhead_mean_pct={pstat("peak_rss_mb_overhead_pct"):.3f}',
 f'paired_peak_rss_overhead_median_pct={pstat("peak_rss_mb_overhead_pct","median"):.3f}',
 f'paired_peak_rss_overhead_p95_pct={pstat("peak_rss_mb_overhead_pct","p95"):.3f}',
 f'paired_peak_rss_overhead_stddev_pct={pstat("peak_rss_mb_overhead_pct","stddev"):.3f}',
 f'paired_rank0_pt_overhead_mean_pct={pstat("rank0_pt_ms_overhead_pct"):.3f}',
 f'paired_rank0_pt_overhead_median_pct={pstat("rank0_pt_ms_overhead_pct","median"):.3f}',
 f'paired_rank0_pt_overhead_p95_pct={pstat("rank0_pt_ms_overhead_pct","p95"):.3f}',
 f'paired_rank0_pt_overhead_stddev_pct={pstat("rank0_pt_ms_overhead_pct","stddev"):.3f}',
 'claim_scope=runtime-and-accountability-overhead; production-backend-validation-reported-separately']
open(out,'w').write('\n'.join(lines)+'\n')
PY
cat "$OUT/SUMMARY.txt"
echo "raw=$RAW"
echo "summary=$OUT/summary_stats.csv"
echo "results=$OUT"
