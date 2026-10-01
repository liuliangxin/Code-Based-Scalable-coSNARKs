#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path

def read_summary(path):
    out = {}
    for line in path.read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--party-results", type=Path)
    ap.add_argument("--release-gate-results", type=Path)
    args = ap.parse_args()
    summary_path = args.results / "SUMMARY.txt"
    stats_path = args.results / "summary_stats.csv"
    if not summary_path.is_file() or not stats_path.is_file():
        raise SystemExit("missing localization-scaling artifacts")
    text = summary_path.read_text()
    if "PVIA LOCALIZATION SCALING: PASS" not in text:
        raise SystemExit("localization scaling did not pass")
    s = read_summary(summary_path)
    qs = [int(x) for x in s["q_sizes"].split(",")]
    args.out.mkdir(parents=True, exist_ok=True)

    md = [
        "# Private localization scaling",
        "",
        "The recursive dispute narrows the failed operation set by binary subset tests. "
        "Depth is logarithmic in candidate-set size, while wall-clock work also includes "
        "the authenticated subset tests at each level.",
        "",
        "| Q | Depth | First checks | First dispute ms | First auth KB | Last checks | Last dispute ms | Last auth KB |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    tex_rows = []
    plot_rows = [["q","fault","depth","subset_checks","batch_mean_ms","dispute_mean_ms","dispute_p95_ms","dispute_auth_sent_kb"]]
    for q in qs:
        vals = {}
        for fault in ("first", "last"):
            pre = f"q{q}_{fault}_"
            vals[fault] = {
                "depth": int(float(s[pre+"depth"])),
                "checks": int(float(s[pre+"subset_checks"])),
                "batch": float(s[pre+"batch_mean_ms"]),
                "dispute": float(s[pre+"dispute_mean_ms"]),
                "p95": float(s[pre+"dispute_p95_ms"]),
                "kb": float(s[pre+"dispute_auth_sent_kb"]),
            }
            plot_rows.append([q, fault, vals[fault]["depth"], vals[fault]["checks"], vals[fault]["batch"], vals[fault]["dispute"], vals[fault]["p95"], vals[fault]["kb"]])
        a, b = vals["first"], vals["last"]
        md.append(f"| {q} | {a['depth']} | {a['checks']} | {a['dispute']:.1f} | {a['kb']:.1f} | {b['checks']} | {b['dispute']:.1f} | {b['kb']:.1f} |")
        tex_rows.append(f"{q} & {a['depth']} & {a['checks']} & {a['dispute']:.1f} & {a['kb']:.1f} & {b['checks']} & {b['dispute']:.1f} & {b['kb']:.1f} " + r"\\")
    (args.out / "localization_scaling.md").write_text("\n".join(md) + "\n")

    tex = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Private recursive-localization scaling on four parties. First places the faulty residual in the first branch; Last places it in the last branch, causing two subset checks per level.}",
        r"\label{tab:pvia-localization-scaling}",
        r"\resizebox{\columnwidth}{!}{%",
        r"\begin{tabular}{rrrrrrrr}",
        r"\toprule",
        r"$|\mathcal Q|$ & Depth & First checks & First ms & First KB & Last checks & Last ms & Last KB \\",
        r"\midrule",
        *tex_rows,
        r"\bottomrule",
        r"\end{tabular}}",
        r"\end{table}",
        "",
    ]
    (args.out / "localization_scaling.tex").write_text("\n".join(tex))
    with (args.out / "localization_scaling_plot.csv").open("w", newline="") as f:
        csv.writer(f).writerows(plot_rows)

    first0 = float(s[f"q{qs[0]}_first_dispute_mean_ms"])
    first1 = float(s[f"q{qs[-1]}_first_dispute_mean_ms"])
    last0 = float(s[f"q{qs[0]}_last_dispute_mean_ms"])
    last1 = float(s[f"q{qs[-1]}_last_dispute_mean_ms"])
    d0 = int(float(s[f"q{qs[0]}_first_depth"]))
    d1 = int(float(s[f"q{qs[-1]}_first_depth"]))
    fc0 = int(float(s[f"q{qs[0]}_first_subset_checks"]))
    fc1 = int(float(s[f"q{qs[-1]}_first_subset_checks"]))
    lc0 = int(float(s[f"q{qs[0]}_last_subset_checks"]))
    lc1 = int(float(s[f"q{qs[-1]}_last_subset_checks"]))
    paragraph = (
        r"\paragraph{Private localization scaling.} "
        + f"We vary the number of candidate residual obligations from ${qs[0]}$ to ${qs[-1]}$ while injecting one failure. "
        + r"The measured recursive depth matches $\log_2|\mathcal Q|$ exactly: "
        + f"it grows from {d0} to {d1} levels. "
        + f"The first-branch case uses {fc0} to {fc1} authenticated subset tests, whereas the last-branch case uses {lc0} to {lc1}. "
        + f"Dispute time rises from {first0:.1f} to {first1:.1f}~ms for the first branch and from {last0:.1f} to {last1:.1f}~ms for the last branch. "
        + r"Thus the measurements support logarithmic interaction depth, not logarithmic wall-clock work: each level still constructs and checks an authenticated residual fingerprint over a subset."
    )
    (args.out / "localization_scaling_paragraph.tex").write_text(paragraph + "\n")

    summary = [
        "PVIA_LOCALIZATION_EVALUATION_BUNDLE: PASS",
        f"q_min={qs[0]}",
        f"q_max={qs[-1]}",
        f"depth_min={d0}",
        f"depth_max={d1}",
        f"first_checks_min={fc0}",
        f"first_checks_max={fc1}",
        f"last_checks_min={lc0}",
        f"last_checks_max={lc1}",
        f"first_dispute_ms_min={first0:.6f}",
        f"first_dispute_ms_max={first1:.6f}",
        f"last_dispute_ms_min={last0:.6f}",
        f"last_dispute_ms_max={last1:.6f}",
        "claim_scope=logarithmic-recursive-depth-not-logarithmic-wall-clock",
        f"source={args.results.resolve()}",
    ]
    if args.party_results:
        party_summary_path = args.party_results / "SUMMARY.txt"
        party_csv_path = args.party_results / "party_scaling.csv"
        if not party_summary_path.is_file() or not party_csv_path.is_file():
            raise SystemExit("missing party-scaling artifacts")
        party_text = party_summary_path.read_text()
        if "PVIA LOCALIZATION PARTY SCALING: PASS" not in party_text:
            raise SystemExit("party scaling did not pass")
        party_rows = list(csv.DictReader(party_csv_path.open(newline="")))
        pmd = [
            "# Private localization party scaling",
            "",
            "| Parties | Q | Fault | Depth | Checks | Batch ms | Dispute ms | Auth KB |",
            "|---:|---:|:---|---:|---:|---:|---:|---:|",
        ]
        for row in party_rows:
            pmd.append(
                f"| {row['parties']} | {row['q']} | {row['fault']} | "
                f"{row['depth']} | {row['subset_checks']} | "
                f"{float(row['batch_mean_ms']):.1f} | "
                f"{float(row['dispute_mean_ms']):.1f} | "
                f"{float(row['dispute_auth_sent_kb']):.1f} |")
        (args.out / "localization_party_scaling.md").write_text(
            "\n".join(pmd) + "\n")

        ptex_rows = []
        for row in party_rows:
            ptex_rows.append(
                f"{row['parties']} & {row['fault']} & {row['depth']} & "
                f"{row['subset_checks']} & {float(row['batch_mean_ms']):.1f} & "
                f"{float(row['dispute_mean_ms']):.1f} & "
                f"{float(row['dispute_auth_sent_kb']):.1f} " + r"\\")
        ptex = [
            r"\begin{table}[t]",
            r"\centering",
            r"\caption{Party-count scaling for private localization at $|\mathcal Q|=32$.}",
            r"\label{tab:pvia-localization-party-scaling}",
            r"\resizebox{\columnwidth}{!}{%",
            r"\begin{tabular}{lrrrrrr}",
            r"\toprule",
            r"$N$ & Fault & Depth & Checks & Batch ms & Dispute ms & Auth KB \\",
            r"\midrule",
            *ptex_rows,
            r"\bottomrule",
            r"\end{tabular}}",
            r"\end{table}",
            "",
        ]
        (args.out / "localization_party_scaling.tex").write_text(
            "\n".join(ptex))
        summary.append("party_scaling=PASS")
        summary.append(f"party_source={args.party_results.resolve()}")

    if args.release_gate_results:
        rg = args.release_gate_results / "SUMMARY.txt"
        if not rg.is_file():
            raise SystemExit("missing release-gate summary")
        rg_text = rg.read_text()
        if "PVIA RELEASE GATE MATRIX: PASS" not in rg_text:
            raise SystemExit("release-gate matrix did not pass")
        rkv = {}
        for line in rg_text.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                rkv[k.strip()] = v.strip()
        cases = [
            ("coSumcheck", "cosumcheck"),
            ("Distributed Sumcheck", "distributed_sumcheck"),
            ("Encoding", "encoding"),
            ("PCS open", "pcs_open"),
            ("PCS batch open", "pcs_batch_open"),
        ]
        rmd = [
            "# Release-gate fault injection",
            "",
            "| Release family | Positive path | Injected deviation |",
            "|:---|:---|:---|",
        ]
        for label, key in cases:
            rmd.append(
                f"| {label} | {rkv[key + '_positive']} | "
                f"{rkv[key + '_injected']} |")
        rmd += [
            "",
            f"Exact release scope: {rkv.get('exact_scope', 'unknown')}.",
            f"Private localization coverage: {rkv.get('private_localization', 'unknown')}.",
            f"Other families: {rkv.get('other_families', 'unknown')}.",
        ]
        (args.out / "release_gate_fault_injection.md").write_text(
            "\n".join(rmd) + "\n")
        summary.append("release_gate_fault_injection=PASS")
        summary.append(
            f"release_gate_source={args.release_gate_results.resolve()}")

    (args.out / "LOCALIZATION_EVALUATION_SUMMARY.txt").write_text(
        "\n".join(summary) + "\n")
    print("\n".join(summary))
if __name__ == "__main__":
    main()
