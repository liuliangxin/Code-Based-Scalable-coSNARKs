#!/usr/bin/env python3
import argparse, csv, math, statistics
from pathlib import Path
MIB=1024.0*1024.0

def rows(p):
    with p.open(newline='',encoding='utf-8-sig') as f: return list(csv.DictReader(f))
def kv(p):
    d={}
    for line in p.read_text(encoding='utf-8-sig').splitlines():
        if '=' in line:
            k,v=line.split('=',1); d[k.strip()]=v.strip()
    return d
def pct(a,b): return (b/a-1.0)*100.0 if a else 0.0
def p95(xs):
    xs=sorted(xs); x=.95*(len(xs)-1); lo=math.floor(x); hi=math.ceil(x)
    return xs[lo] if lo==hi else xs[lo]+(xs[hi]-xs[lo])*(x-lo)
def pair_metric(ds,es,key,scale=1.0):
    dv=[float(r[key])*scale for r in ds]; ev=[float(r[key])*scale for r in es]
    ov=[pct(a,b) for a,b in zip(dv,ev)]
    return statistics.mean(dv),statistics.mean(ev),statistics.median(ov),p95(ov)

def point_data(point, parties, repeats):
    raw=rows(point/'raw_runs.csv'); by={}
    for r in raw: by.setdefault(int(r['iteration']),{})[r['scenario']]=r
    if sorted(by)!=list(range(1,repeats+1)): raise ValueError(f'{point}: incomplete iterations')
    ds=[]; es=[]
    zero_fields=['sum_auth_sent_bytes','sum_control_sent_bytes','sum_transfer_meta_recv_bytes',
                 'sum_initial_validity_control_sent_bytes','sum_consistency_provider_control_sent_bytes',
                 'sum_public_direct_validation_control_sent_bytes','unclassified_control_sent_bytes']
    for i in sorted(by):
        if set(by[i])!={'disabled','enabled'}: raise ValueError(f'{point}: unpaired iteration {i}')
        d,e=by[i]['disabled'],by[i]['enabled']; ds.append(d); es.append(e)
        if int(d['world_size'])!=parties or int(e['world_size'])!=parties: raise ValueError(f'{point}: world size')
        if d['interaction_rounds']!=e['interaction_rounds']: raise ValueError(f'{point}: native rounds changed')
        for f in zero_fields:
            if abs(float(d[f]))>1e-9: raise ValueError(f'{point}: disabled emitted {f}')
        if abs(float(d['reported_comm_mb'])-float(e['reported_comm_mb']))>1e-9:
            raise ValueError(f'{point}: legacy communication changed')
    return ds,es

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--matrix-dir',type=Path,required=True); ap.add_argument('--out',type=Path,required=True)
    a=ap.parse_args(); a.out.mkdir(parents=True,exist_ok=True)
    matrix=[r for r in rows(a.matrix_dir/'regression_matrix.csv') if r['status']=='PASS']; out=[]
    for mr in matrix:
        n=int(mr['parties']); m=int(mr['m_log']); rep=int(mr['repeats']); warm=int(mr['warmup']); p=Path(mr['result_dir']); s=kv(p/'SUMMARY.txt')
        ds,es=point_data(p,n,rep)
        b_e2e,e_e2e,e2e_med,e2e_p95=pair_metric(ds,es,'max_program_total_ns',1e-6)
        b_pt,e_pt,pt_med,pt_p95=pair_metric(ds,es,'rank0_pt_s',1000.0)
        b_v,e_v,v_med,v_p95=pair_metric(ds,es,'verifier_total_s',1000.0)
        b_pf,e_pf,pf_med,pf_p95=pair_metric(ds,es,'proof_kb')
        b_c,e_c,c_med,c_p95=pair_metric(ds,es,'reported_comm_mb')
        br=int(float(ds[0]['interaction_rounds'])); er=int(float(es[0]['interaction_rounds']))
        online=float(s['enabled_online_accounted_comm_mean_mb']); full=float(s['enabled_accounted_comm_mean_mb'])
        added_online=online-e_c; added_full=full-e_c
        sync=float(s['enabled_control_collectives_per_rank']); unclassified=float(s['enabled_unclassified_control_mean_bytes'])
        if unclassified!=0 or int(float(s['enabled_control_scope_partition_complete']))!=1: raise ValueError(f'{p}: incomplete control scope')
        auth=float(s['enabled_authenticated_control_sent_mean_bytes']); control=float(s['enabled_control_sent_mean_bytes']); meta=float(s['enabled_pvia_metadata_recv_mean_bytes'])
        validity=float(s['enabled_initial_validity_control_mean_bytes']); provider=float(s['enabled_consistency_provider_control_mean_bytes']); direct=float(s['enabled_public_direct_validation_control_mean_bytes'])
        online_check=e_c+(auth+validity+provider+direct+meta)/MIB; full_check=e_c+(auth+control+meta)/MIB
        if abs(online-online_check)>2e-6 or abs(full-full_check)>2e-6: raise ValueError(f'{p}: accounted communication formula mismatch')
        out.append(dict(parties=n,m_log=m,repeats=rep,warmup=warm,
          baseline_e2e_ms=b_e2e,pvia_e2e_ms=e_e2e,e2e_median_overhead_pct=e2e_med,e2e_p95_overhead_pct=e2e_p95,
          baseline_rank0_prover_ms=b_pt,pvia_rank0_prover_ms=e_pt,rank0_median_overhead_pct=pt_med,rank0_p95_overhead_pct=pt_p95,
          baseline_verifier_ms=b_v,pvia_verifier_ms=e_v,verifier_median_overhead_pct=v_med,verifier_p95_overhead_pct=v_p95,
          baseline_proof_kb=b_pf,pvia_proof_kb=e_pf,proof_median_change_pct=pf_med,proof_p95_change_pct=pf_p95,
          baseline_native_rounds=br,pvia_native_rounds=er,native_round_change=er-br,pvia_control_syncs_per_rank=sync,
          baseline_legacy_comm_mb=b_c,pvia_legacy_comm_mb=e_c,legacy_comm_median_overhead_pct=c_med,legacy_comm_p95_overhead_pct=c_p95,
          baseline_instrumented_accounted_comm_mb=b_c,added_online_accountability_mb=added_online,added_full_accountability_mb=added_full,
          pvia_online_accounted_comm_mb=online,pvia_full_accounted_comm_mb=full,
          instrumented_online_factor=online/b_c,instrumented_full_factor=full/b_c,
          instrumented_online_overhead_pct=pct(b_c,online),instrumented_full_overhead_pct=pct(b_c,full),
          auth_envelope_bytes=auth,control_bytes=control,metadata_bytes=meta,
          disabled_accountability_extras_zero=1,control_scope_partition_complete=1))
    out.sort(key=lambda r:(r['parties'],r['m_log']))
    with (a.out/'fair_baseline_vs_pvia.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(out[0])); w.writeheader(); w.writerows(out)
    md=['# Fair baseline → PVIA paired comparison','',
        'Same binary/host/parameters; PVIA_ENABLE=0 vs 1; paired alternating order. Legacy communication and instrumented PVIA traffic are reported separately.', '',
        '| N | log M | Base E2E ms | PVIA E2E ms | E2E median Δ | Rank0 median Δ | Verifier median Δ | Proof median Δ | Native rounds Δ | Ctrl syncs/rank |',
        '|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for r in out: md.append(f"| {r['parties']} | {r['m_log']} | {r['baseline_e2e_ms']:.1f} | {r['pvia_e2e_ms']:.1f} | {r['e2e_median_overhead_pct']:.1f}% | {r['rank0_median_overhead_pct']:.1f}% | {r['verifier_median_overhead_pct']:.1f}% | {r['proof_median_change_pct']:.1f}% | {r['native_round_change']} | {r['pvia_control_syncs_per_rank']:.0f} |")
    md += ['', '| N | log M | Native/legacy MB | Legacy Δ | Added online MB | Added full MB | PVIA full MB | Full factor |',
           '|---:|---:|---:|---:|---:|---:|---:|---:|']
    for r in out: md.append(f"| {r['parties']} | {r['m_log']} | {r['baseline_legacy_comm_mb']:.3f} | {r['legacy_comm_median_overhead_pct']:.1f}% | {r['added_online_accountability_mb']:.3f} | {r['added_full_accountability_mb']:.3f} | {r['pvia_full_accounted_comm_mb']:.3f} | {r['instrumented_full_factor']:.2f}x |")
    (a.out/'fair_baseline_vs_pvia.md').write_text('\n'.join(md)+'\n')
    bs=chr(92)
    runtime_rows=[]
    comm_rows=[]
    for r in out:
        runtime_rows.append(
          f"{r['parties']} & {r['m_log']} & {r['baseline_e2e_ms']:.1f} & "
          f"{r['pvia_e2e_ms']:.1f} & {r['e2e_median_overhead_pct']:.1f}{bs}% & "
          f"{r['verifier_median_overhead_pct']:.1f}{bs}% & "
          f"{r['proof_median_change_pct']:.1f}{bs}% & "
          f"{r['pvia_control_syncs_per_rank']:.0f} {bs}{bs}")
        comm_rows.append(
          f"{r['parties']} & {r['m_log']} & {r['baseline_legacy_comm_mb']:.3f} & "
          f"{r['legacy_comm_median_overhead_pct']:.1f}{bs}% & "
          f"{r['added_online_accountability_mb']:.3f} & "
          f"{r['added_full_accountability_mb']:.3f} & "
          f"{r['pvia_full_accounted_comm_mb']:.3f} & "
          f"{r['instrumented_full_factor']:.2f}${bs}times$ {bs}{bs}")

    runtime_tex=[
      f"{bs}begin{{table*}}[t]",
      f"{bs}centering",
      f"{bs}caption{{Incremental runtime cost of PVIA relative to the same code-based collaborative SNARK implementation with accountability disabled. Base and PVIA times are means over ten measured runs after two warm-ups; percentage changes are medians of the ten paired per-run changes. Native proof rounds are unchanged, so we report PVIA control synchronizations separately.}}",
      f"{bs}label{{tab:pvia-fair-runtime}}",
      f"{bs}begin{{tabular}}{{rrrrrrrr}}",
      f"{bs}toprule",
      f"$N$ & ${bs}log M$ & Base E2E (ms) & PVIA E2E (ms) & E2E ${bs}Delta$ & Verifier ${bs}Delta$ & Proof ${bs}Delta$ & Ctrl syncs/rank {bs}{bs}",
      f"{bs}midrule",
      *runtime_rows,
      f"{bs}bottomrule",
      f"{bs}end{{tabular}}",
      f"{bs}end{{table*}}",
      "",
    ]
    (a.out/'fair_baseline_vs_pvia_runtime.tex').write_text(chr(10).join(runtime_tex)+chr(10))

    comm_tex=[
      f"{bs}begin{{table*}}[t]",
      f"{bs}centering",
      f"{bs}caption{{Communication accounting for the fair PVIA comparison. The legacy column is the original implementation's native protocol counter and is unchanged by PVIA. Added online/full columns contain explicitly instrumented PVIA accountability traffic. The final total and factor therefore use an instrumented scope (legacy native traffic plus PVIA traffic), not a cross-hardware reproduction of the original paper's LAN/WAN byte totals.}}",
      f"{bs}label{{tab:pvia-fair-communication}}",
      f"{bs}begin{{tabular}}{{rrrrrrrr}}",
      f"{bs}toprule",
      f"$N$ & ${bs}log M$ & Native (MB) & Native ${bs}Delta$ & Added online (MB) & Added full (MB) & PVIA full (MB) & Factor {bs}{bs}",
      f"{bs}midrule",
      *comm_rows,
      f"{bs}bottomrule",
      f"{bs}end{{tabular}}",
      f"{bs}end{{table*}}",
      "",
    ]
    (a.out/'fair_baseline_vs_pvia_communication.tex').write_text(chr(10).join(comm_tex)+chr(10))

    e2=[r['e2e_median_overhead_pct'] for r in out]; pt=[r['rank0_median_overhead_pct'] for r in out]; vv=[r['verifier_median_overhead_pct'] for r in out]; pp=[r['proof_median_change_pct'] for r in out]; ff=[r['instrumented_full_factor'] for r in out]; ss=[r['pvia_control_syncs_per_rank'] for r in out]
    summary=['PVIA_FAIR_BASELINE_COMPARISON: PASS',f'points={len(out)}',f'repeats={out[0]["repeats"]}',f'warmup={out[0]["warmup"]}',
      'baseline=PVIA_ENABLE_0_same_binary_same_host_same_parameters','disabled_accountability_extras_zero=1','legacy_reported_comm_change=0','native_round_change=0',
      f'e2e_median_overhead_pct={min(e2):.3f}..{max(e2):.3f}',f'rank0_median_overhead_pct={min(pt):.3f}..{max(pt):.3f}',
      f'verifier_median_overhead_pct={min(vv):.3f}..{max(vv):.3f}',f'proof_median_change_pct={min(pp):.3f}..{max(pp):.3f}',
      f'instrumented_full_factor_x={min(ff):.6f}..{max(ff):.6f}',f'control_syncs_per_rank={min(ss):.0f}..{max(ss):.0f}',
      'communication_scope=legacy_native_counter_plus_explicit_pvia_accountability_traffic','claim_scope=incremental_accountability_overhead_not_original_paper_lan_wan_reproduction',f'source={a.matrix_dir.resolve()}']
    (a.out/'SUMMARY.txt').write_text('\n'.join(summary)+'\n'); print('\n'.join(summary))
    paragraph=(
      f"{bs}paragraph{{Incremental accountability cost.}} "
      "We compare PVIA against the same code-based collaborative SNARK binary with "
      "accountability disabled, using identical parameters and ten paired runs after "
      "two warm-ups with alternating execution order. Across the nine supported points, "
      f"the paired-median end-to-end overhead ranges from {min(e2):.1f}{bs}% to {max(e2):.1f}{bs}%. "
      f"Verifier changes range from {min(vv):.1f}{bs}% to {max(vv):.1f}{bs}%, while proof-size "
      f"changes range from {min(pp):.1f}{bs}% to {max(pp):.1f}{bs}%. The original native "
      "communication counter and native proof-round count are unchanged; PVIA adds "
      f"{min(ss):.0f}--{max(ss):.0f} control synchronizations per rank plus explicitly "
      "instrumented accountability traffic. Under this instrumented scope, full communication "
      f"is {min(ff):.2f}{bs}times--{max(ff):.2f}{bs}times the baseline native counter. "
      "These ratios quantify incremental accountability cost in our implementation and are "
      "not presented as a reproduction of the original paper's absolute LAN/WAN measurements."
    )
    (a.out/'fair_baseline_vs_pvia_paragraph.tex').write_text(paragraph+chr(10))
if __name__=='__main__': main()
