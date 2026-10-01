#!/usr/bin/env python3
import argparse
import csv
import math
import statistics
from pathlib import Path

TOP_LEVEL_FIELDS = [
    "runtime_init_ns",
    "preprocessing_ns",
    "initial_validity_ns",
    "public_direct_validation_ns",
    "consistency_provider_ns",
]
CROSS_FIELDS = [
    "transfer_meta_seal_ns",
    "transfer_meta_observe_ns",
    "transfer_meta_verify_ns",
]

def csv_rows(path):
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))

def p95(xs):
    xs = sorted(xs)
    x = 0.95 * (len(xs) - 1)
    lo, hi = math.floor(x), math.ceil(x)
    return xs[lo] if lo == hi else xs[lo] + (xs[hi] - xs[lo]) * (x - lo)

def stats(xs):
    return {"mean":statistics.mean(xs),"median":statistics.median(xs),"p95":p95(xs),"min":min(xs),"max":max(xs)}

def metric_rows(directory):
    rows = []
    for path in sorted(directory.glob("pvia_metrics_rank_*.csv")):
        data = csv_rows(path)
        if len(data) != 1:
            raise ValueError(f"{path}: expected one metrics row")
        rows.append(data[0])
    if not rows:
        raise ValueError(f"{directory}: no rank metrics")
    world = {int(r["world_size"]) for r in rows}
    if len(world) != 1 or len(rows) != next(iter(world)):
        raise ValueError(f"{directory}: incomplete rank metrics")
    return rows

def critical_rank_timings(directory):
    rows = metric_rows(directory)
    per_rank = []
    for r in rows:
        top = sum(int(r[k]) for k in TOP_LEVEL_FIELDS)
        cross_unique = int(r["transfer_meta_seal_ns"]) + int(r["transfer_meta_observe_ns"])
        per_rank.append({
            "top_level_ns": top,
            "runtime_init_ns": int(r["runtime_init_ns"]),
            "preprocessing_ns": int(r["preprocessing_ns"]),
            "initial_validity_ns": int(r["initial_validity_ns"]),
            "public_direct_validation_ns": int(r["public_direct_validation_ns"]),
            "consistency_provider_ns": int(r["consistency_provider_ns"]),
            "metadata_cross_unique_ns": cross_unique,
            "metadata_seal_ns": int(r["transfer_meta_seal_ns"]),
            "metadata_observe_ns": int(r["transfer_meta_observe_ns"]),
            "metadata_verify_ns": int(r["transfer_meta_verify_ns"]),
        })
    return {key:max(r[key] for r in per_rank) for key in per_rank[0]}

def loglog_exponent(points, key):
    xs = [math.log(float(r["parties"])) for r in points]
    ys = [math.log(float(r[key])) for r in points if float(r[key]) > 0]
    if len(ys) != len(xs) or len(xs) < 2:
        return float("nan")
    xm, ym = statistics.mean(xs), statistics.mean(ys)
    den = sum((x-xm)**2 for x in xs)
    return sum((x-xm)*(y-ym) for x,y in zip(xs,ys))/den

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--results",type=Path,required=True)
    ap.add_argument("--out",type=Path,required=True)
    args=ap.parse_args()
    args.out.mkdir(parents=True,exist_ok=True)
    output=[]
    for point in sorted(args.results.glob("n*"), key=lambda p:int(p.name[1:]) if p.name[1:].isdigit() else 10**9):
        if not point.is_dir() or not point.name[1:].isdigit():
            continue
        n=int(point.name[1:])
        raw=csv_rows(point/"raw_runs.csv")
        by={}
        for r in raw:
            by.setdefault(int(r["iteration"]),{})[r["scenario"]]=r
        if not by:
            continue
        e2e_delta=[]; top=[]; shares=[]
        module={k:[] for k in TOP_LEVEL_FIELDS}
        cross={k:[] for k in ["metadata_cross_unique_ns","metadata_seal_ns","metadata_observe_ns","metadata_verify_ns"]}
        for iteration,pair in sorted(by.items()):
            if set(pair)!={"disabled","enabled"}:
                raise ValueError(f"{point}: unpaired iteration {iteration}")
            d,e=pair["disabled"],pair["enabled"]
            for k in ["max_runtime_init_ns","max_preprocessing_ns","max_initial_validity_ns","max_public_direct_validation_ns","max_consistency_provider_ns"]:
                if abs(float(d[k]))>1e-9:
                    raise ValueError(f"{point}: disabled timing {k} is nonzero")
            delta_ms=(float(e["max_program_total_ns"])-float(d["max_program_total_ns"]))/1e6
            timing=critical_rank_timings(point/f"enabled_{iteration}"/"metrics")
            top_ms=timing["top_level_ns"]/1e6
            e2e_delta.append(delta_ms); top.append(top_ms)
            shares.append(100.0*top_ms/delta_ms if delta_ms else 0.0)
            for k in TOP_LEVEL_FIELDS: module[k].append(timing[k]/1e6)
            for k in cross: cross[k].append(timing[k]/1e6)
        es=stats(e2e_delta); ts=stats(top); ss=stats(shares)
        row={
            "parties":n,"pairs":len(by),
            "e2e_delta_mean_ms":es["mean"],"e2e_delta_median_ms":es["median"],"e2e_delta_p95_ms":es["p95"],
            "top_level_timed_mean_ms":ts["mean"],"top_level_timed_median_ms":ts["median"],"top_level_share_median_pct":ss["median"],
            "runtime_init_median_ms":stats(module["runtime_init_ns"])["median"],
            "preprocessing_median_ms":stats(module["preprocessing_ns"])["median"],
            "initial_validity_median_ms":stats(module["initial_validity_ns"])["median"],
            "public_direct_median_ms":stats(module["public_direct_validation_ns"])["median"],
            "provider_median_ms":stats(module["consistency_provider_ns"])["median"],
            "metadata_cross_unique_median_ms":stats(cross["metadata_cross_unique_ns"])["median"],
            "metadata_seal_median_ms":stats(cross["metadata_seal_ns"])["median"],
            "metadata_observe_median_ms":stats(cross["metadata_observe_ns"])["median"],
            "metadata_verify_subset_median_ms":stats(cross["metadata_verify_ns"])["median"],
        }
        row["initial_validity_share_of_top_level_pct"]=100.0*row["initial_validity_median_ms"]/row["top_level_timed_median_ms"] if row["top_level_timed_median_ms"] else 0.0
        output.append(row)
    if not output: raise SystemExit("no timing points found")
    with (args.out/"accountability_runtime_breakdown.csv").open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(output[0])); w.writeheader(); w.writerows(output)
    md=["# Accountability runtime breakdown","",
        "Top-level timers are non-overlapping PVIA module scopes. For each run we sum those timers per rank and then take the maximum rank, avoiding a sum-of-independent-maxima artifact. Transfer-metadata timers are cross-cutting and are reported separately; observe includes verify, so verify is a subset and is never added again.","",
        "| N | Paired E2E delta ms | Timed top-level ms | Timed share | Init-valid ms | Preproc ms | Public-direct ms | Runtime-init ms | Init-valid share of timed |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in output:
        md.append(f"| {r['parties']} | {r['e2e_delta_median_ms']:.1f} | {r['top_level_timed_median_ms']:.1f} | {r['top_level_share_median_pct']:.1f}% | {r['initial_validity_median_ms']:.1f} | {r['preprocessing_median_ms']:.1f} | {r['public_direct_median_ms']:.1f} | {r['runtime_init_median_ms']:.2f} | {r['initial_validity_share_of_top_level_pct']:.1f}% |")
    md += ["","| N | Metadata seal ms | Metadata observe ms | Verify subset ms | Seal+observe diagnostic ms |","|---:|---:|---:|---:|---:|"]
    for r in output:
        md.append(f"| {r['parties']} | {r['metadata_seal_median_ms']:.1f} | {r['metadata_observe_median_ms']:.1f} | {r['metadata_verify_subset_median_ms']:.1f} | {r['metadata_cross_unique_median_ms']:.1f} |")
    md += ["","The metadata row is diagnostic rather than additive with the top-level row because transfer metadata is cross-cutting and can occur inside or alongside higher-level protocol phases."]
    (args.out/"accountability_runtime_breakdown.md").write_text("\n".join(md)+"\n")
    bs=chr(92); tex_rows=[]
    for r in output:
        tex_rows.append(f"{r['parties']} & {r['e2e_delta_median_ms']:.1f} & {r['top_level_timed_median_ms']:.1f} & {r['top_level_share_median_pct']:.1f}{bs}% & {r['initial_validity_median_ms']:.1f} & {r['preprocessing_median_ms']:.1f} & {r['public_direct_median_ms']:.1f} & {r['initial_validity_share_of_top_level_pct']:.1f}{bs}% {bs}{bs}")
    tex=[f"{bs}begin{{table*}}[t]",f"{bs}centering",
         f"{bs}caption{{Direct timing attribution for the incremental PVIA runtime cost at the paper-aligned workload shape. E2E delta is the paired median. Top-level PVIA timers are summed per rank before taking the maximum rank, so the timed share does not sum independent rank maxima. Cross-cutting transfer-metadata timings are reported separately and are not added to this table.}}",
         f"{bs}label{{tab:pvia-runtime-breakdown}}",f"{bs}begin{{tabular}}{{rrrrrrrr}}",f"{bs}toprule",
         f"$N$ & E2E delta (ms) & Timed (ms) & Timed share & Init-valid (ms) & Preproc (ms) & Direct (ms) & Init-valid/timed {bs}{bs}",
         f"{bs}midrule",*tex_rows,f"{bs}bottomrule",f"{bs}end{{tabular}}",f"{bs}end{{table*}}",""]
    (args.out/"accountability_runtime_breakdown.tex").write_text("\n".join(tex))
    iv_exp=loglog_exponent(output,"initial_validity_median_ms")
    meta_exp=loglog_exponent(output,"metadata_observe_median_ms")
    timed_shares=[r["top_level_share_median_pct"] for r in output]
    iv_shares=[r["initial_validity_share_of_top_level_pct"] for r in output]
    paragraph=(f"{bs}paragraph{{Where does the runtime overhead go?}} "
      "Direct module timers show that the dominant explicitly timed component is the initial-validity gate. "
      f"Its paired median critical-rank time rises from {output[0]['initial_validity_median_ms']:.1f}~ms at $N={output[0]['parties']}$ to {output[-1]['initial_validity_median_ms']:.1f}~ms at $N={output[-1]['parties']}$, accounting for {min(iv_shares):.1f}{bs}%--{max(iv_shares):.1f}{bs}% of the non-overlapping top-level PVIA time. "
      f"Together, the directly timed top-level modules account for a median {min(timed_shares):.1f}{bs}%--{max(timed_shares):.1f}{bs}% of the paired E2E delta across the measured party counts. "
      "Transfer-metadata verification is cross-cutting rather than a separate additive phase: observe includes verify, so its timings are reported diagnostically and not summed with the top-level attribution. "
      "The remaining delta includes authenticated-envelope processing, secure-transfer work, collective synchronization, and baseline run-to-run variation that are not isolated by a non-overlapping module timer.")
    (args.out/"accountability_runtime_breakdown_paragraph.tex").write_text(paragraph+"\n")
    lines=["PVIA_ACCOUNTABILITY_RUNTIME_BREAKDOWN: PASS",
      "parties="+",".join(str(r["parties"]) for r in output),
      "pairs="+",".join(str(r["pairs"]) for r in output),
      f"top_level_share_median_pct={min(timed_shares):.3f}..{max(timed_shares):.3f}",
      f"initial_validity_share_of_top_level_pct={min(iv_shares):.3f}..{max(iv_shares):.3f}",
      f"initial_validity_empirical_party_exponent={iv_exp:.6f}",
      f"metadata_observe_empirical_party_exponent={meta_exp:.6f}",
      "metadata_observe_includes_verify=1","top_level_timers_nonoverlapping=1","cross_cutting_metadata_not_added_to_top_level=1",
      f"source={args.results.resolve()}"]
    (args.out/"SUMMARY.txt").write_text("\n".join(lines)+"\n"); print("\n".join(lines))
if __name__=="__main__": main()
