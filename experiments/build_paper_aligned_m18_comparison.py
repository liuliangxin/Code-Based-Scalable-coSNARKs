#!/usr/bin/env python3
import argparse, csv, re
from pathlib import Path
from build_accountability_tax_evaluation import pair_stats, read_kv

ZERO_FIELDS = [
    "sum_auth_sent_bytes", "sum_control_sent_bytes", "sum_transfer_meta_recv_bytes",
    "sum_initial_validity_control_sent_bytes", "sum_consistency_provider_control_sent_bytes",
    "sum_public_direct_validation_control_sent_bytes", "unclassified_control_sent_bytes",
]

def raw_rows(path):
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))

def validate_point(point, parties):
    raw = raw_rows(point / "raw_runs.csv")
    by = {}
    for row in raw:
        by.setdefault(int(row["iteration"]), {})[row["scenario"]] = row
    if not by:
        raise ValueError(f"{point}: no measured rows")
    native_rounds = set()
    for iteration, pair in sorted(by.items()):
        if set(pair) != {"disabled", "enabled"}:
            raise ValueError(f"{point}: unpaired iteration {iteration}")
        d, e = pair["disabled"], pair["enabled"]
        if int(d["world_size"]) != parties or int(e["world_size"]) != parties:
            raise ValueError(f"{point}: wrong world size")
        for field in ZERO_FIELDS:
            if abs(float(d[field])) > 1e-9:
                raise ValueError(f"{point}: disabled emitted {field}")
        if abs(float(d["reported_comm_mb"]) - float(e["reported_comm_mb"])) > 1e-9:
            raise ValueError(f"{point}: legacy communication changed")
        if d["interaction_rounds"] != e["interaction_rounds"]:
            raise ValueError(f"{point}: native rounds changed")
        native_rounds.add(int(float(d["interaction_rounds"])))
    if len(native_rounds) != 1:
        raise ValueError(f"{point}: inconsistent native rounds")
    return len(by), next(iter(native_rounds))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    points = []
    for p in args.results.iterdir():
        m = re.fullmatch(r"n(\d+)", p.name)
        if m and p.is_dir() and (p / "raw_runs.csv").is_file():
            points.append((int(m.group(1)), p))
    points.sort()
    if not points:
        raise SystemExit("no n<parties> result directories found")

    out, repeats_seen, warmups_seen = [], set(), set()
    for n, point in points:
        paired_count, rounds = validate_point(point, n)
        metrics, repeats = pair_stats(point)
        summary = read_kv(point / "SUMMARY.txt")
        warmup = int(summary["warmup"])
        if repeats != paired_count:
            raise ValueError(f"{point}: paired-count mismatch")
        repeats_seen.add(repeats); warmups_seen.add(warmup)

        base_comm = metrics["baseline_reported_comm_mb"]
        online = float(summary["enabled_online_accounted_comm_mean_mb"])
        full = float(summary["enabled_accounted_comm_mean_mb"])
        control_syncs = float(summary["enabled_control_collectives_per_rank"])
        unclassified = float(summary["enabled_unclassified_control_mean_bytes"])
        scope_complete = int(float(summary["enabled_control_scope_partition_complete"]))
        if unclassified != 0 or scope_complete != 1:
            raise ValueError(f"{point}: incomplete control-traffic partition")
        if abs(metrics["reported_comm_mb_paired_median_overhead_pct"]) > 1e-9:
            raise ValueError(f"{point}: native communication counter changed")

        out.append({
            "parties": n, "repeats": repeats, "warmup": warmup,
            "baseline_e2e_ms": metrics["baseline_total_ms"], "pvia_e2e_ms": metrics["pvia_total_ms"],
            "e2e_median_overhead_pct": metrics["total_ms_paired_median_overhead_pct"],
            "e2e_p95_overhead_pct": metrics["total_ms_paired_p95_overhead_pct"],
            "baseline_rank0_ms": metrics["baseline_rank0_ms"], "pvia_rank0_ms": metrics["pvia_rank0_ms"],
            "rank0_median_overhead_pct": metrics["rank0_ms_paired_median_overhead_pct"],
            "verifier_median_overhead_pct": metrics["verifier_ms_paired_median_overhead_pct"],
            "proof_median_change_pct": metrics["proof_kb_paired_median_overhead_pct"],
            "native_rounds": rounds, "native_round_change": 0, "pvia_control_syncs_per_rank": control_syncs,
            "baseline_legacy_comm_mb": base_comm, "pvia_legacy_comm_mb": metrics["pvia_reported_comm_mb"],
            "legacy_comm_median_overhead_pct": metrics["reported_comm_mb_paired_median_overhead_pct"],
            "added_online_accountability_mb": online - base_comm, "added_full_accountability_mb": full - base_comm,
            "pvia_online_instrumented_comm_mb": online, "pvia_full_instrumented_comm_mb": full,
            "instrumented_online_factor": online / base_comm, "instrumented_full_factor": full / base_comm,
            "disabled_accountability_extras_zero": 1, "control_scope_partition_complete": scope_complete,
        })

    with (args.out / "paper_aligned_m18_comparison.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0])); w.writeheader(); w.writerows(out)

    md = [
        "# Paper-aligned M_LOG=18 baseline -> PVIA comparison", "",
        "Same host/binary/parameters within each paired batch. This is a single-host MPI incremental-accountability comparison, not a reproduction of the original paper's absolute LAN/WAN timings.", "",
        "| N | Base E2E s | PVIA E2E s | E2E median delta | Rank0 median delta | Verifier median delta | Proof median delta | Native rounds delta | Ctrl syncs/rank |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in out:
        md.append(f"| {r['parties']} | {r['baseline_e2e_ms']/1000:.2f} | {r['pvia_e2e_ms']/1000:.2f} | {r['e2e_median_overhead_pct']:.1f}% | {r['rank0_median_overhead_pct']:.1f}% | {r['verifier_median_overhead_pct']:.1f}% | {r['proof_median_change_pct']:.1f}% | {r['native_round_change']} | {r['pvia_control_syncs_per_rank']:.0f} |")
    md += ["", "| N | Native/legacy MB | Legacy delta | Added online MB | Added full MB | PVIA full instrumented MB | Instrumented factor |", "|---:|---:|---:|---:|---:|---:|---:|"]
    for r in out:
        md.append(f"| {r['parties']} | {r['baseline_legacy_comm_mb']:.3f} | {r['legacy_comm_median_overhead_pct']:.1f}% | {r['added_online_accountability_mb']:.3f} | {r['added_full_accountability_mb']:.3f} | {r['pvia_full_instrumented_comm_mb']:.3f} | {r['instrumented_full_factor']:.2f}x |")
    (args.out / "paper_aligned_m18_comparison.md").write_text("\n".join(md) + "\n")

    bs = chr(92); tex_rows = []
    for r in out:
        tex_rows.append(f"{r['parties']} & {r['baseline_e2e_ms']/1000:.2f} & {r['pvia_e2e_ms']/1000:.2f} & {r['e2e_median_overhead_pct']:.1f}{bs}% & {r['rank0_median_overhead_pct']:.1f}{bs}% & {r['verifier_median_overhead_pct']:.1f}{bs}% & {r['proof_median_change_pct']:.1f}{bs}% & {r['pvia_control_syncs_per_rank']:.0f} {bs}{bs}")
    tex = [
        f"{bs}begin{{table*}}[t]", f"{bs}centering",
        f"{bs}caption{{Incremental accountability cost at the paper-aligned large-workload shape (log M=18). Runs are paired on the same host and binary. Percentage changes are paired medians. Native proof rounds and the legacy protocol communication counter are unchanged; PVIA control synchronizations are reported separately.}}",
        f"{bs}label{{tab:pvia-paper-aligned-tax}}", f"{bs}begin{{tabular}}{{rrrrrrrr}}", f"{bs}toprule",
        f"$N$ & Base (s) & PVIA (s) & E2E change & Rank-0 change & Verifier change & Proof change & Ctrl syncs/rank {bs}{bs}", f"{bs}midrule", *tex_rows,
        f"{bs}bottomrule", f"{bs}end{{tabular}}", f"{bs}end{{table*}}", "",
    ]
    (args.out / "paper_aligned_m18_comparison.tex").write_text("\n".join(tex))

    e2=[r["e2e_median_overhead_pct"] for r in out]; vf=[r["verifier_median_overhead_pct"] for r in out]
    pf=[r["proof_median_change_pct"] for r in out]; ff=[r["instrumented_full_factor"] for r in out]
    ss=[r["pvia_control_syncs_per_rank"] for r in out]
    lines = [
        "PVIA_PAPER_ALIGNED_M18_COMPARISON: PASS", "parties=" + ",".join(str(r["parties"]) for r in out),
        "repeats=" + ",".join(str(x) for x in sorted(repeats_seen)), "warmup=" + ",".join(str(x) for x in sorted(warmups_seen)),
        "parameters=m18-sumcheck14-pc15-multree10", "environment=single-host-mpi", "disabled_accountability_extras_zero=1",
        "legacy_protocol_communication_change=0", "native_round_change=0",
        f"e2e_median_overhead_pct={min(e2):.3f}..{max(e2):.3f}", f"verifier_median_overhead_pct={min(vf):.3f}..{max(vf):.3f}",
        f"proof_median_change_pct={min(pf):.3f}..{max(pf):.3f}", f"instrumented_full_factor_x={min(ff):.6f}..{max(ff):.6f}",
        f"control_syncs_per_rank={min(ss):.0f}..{max(ss):.0f}", "absolute_paper_lan_wan_comparison=not_claimed", f"source={args.results.resolve()}",
    ]
    (args.out / "SUMMARY.txt").write_text("\n".join(lines) + "\n"); print("\n".join(lines))

if __name__ == "__main__":
    main()
