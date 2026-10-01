#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path

def read_kv(path):
    out = {}
    for line in Path(path).read_text(errors="replace").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out

def f(v, n=3):
    return f"{float(v):.{n}f}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--abort-latency", type=Path, required=True)
    ap.add_argument("--judge", type=Path, required=True)
    ap.add_argument("--no-framing", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    abort = read_kv(args.abort_latency / "SUMMARY.txt")
    judge = read_kv(args.judge / "SUMMARY.txt")
    nf = read_kv(args.no_framing / "SUMMARY.txt")
    if abort.get("PVIA ABORT LATENCY: PASS") is not None:
        pass
    if "PVIA ABORT LATENCY: PASS" not in (
        args.abort_latency / "SUMMARY.txt").read_text():
        raise SystemExit("abort latency benchmark did not pass")
    if "PVIA ROBUST ABORT JUDGE BENCHMARK: PASS" not in (
        args.judge / "SUMMARY.txt").read_text():
        raise SystemExit("judge benchmark did not pass")
    if "PVIA FAILURE NO-FRAMING MATRIX: PASS" not in (
        args.no_framing / "SUMMARY.txt").read_text():
        raise SystemExit("no-framing matrix did not pass")

    matrix = list(csv.DictReader(
        (args.no_framing / "negative_matrix.csv").open(newline="")))
    negatives = [r for r in matrix if r["result"] in {"REJECT", "UPSTREAM"}]
    if len(matrix) != 11 or len(negatives) != 10:
        raise SystemExit(
            f"unexpected no-framing matrix shape rows={len(matrix)} "
            f"negatives={len(negatives)}")

    args.out.mkdir(parents=True, exist_ok=True)

    md = [
        "# Failure-path evaluation",
        "",
        "## Failure handling latency",
        "",
        "| Path | Mean ms | Median ms | P95 ms | Scope sync ms | "
        "Batch check ms | Certificate verify ms | Runtime cert bytes |",
        "|:---|---:|---:|---:|---:|---:|---:|---:|",
        f"| Publicly attributable abort | "
        f"{f(abort['public_failure_mean_ms'])} | "
        f"{f(abort['public_failure_median_ms'])} | "
        f"{f(abort['public_failure_p95_ms'])} | "
        f"{f(abort['public_scope_sync_mean_ms'])} | "
        f"{f(abort['public_batch_check_mean_ms'])} | "
        f"{f(abort['public_cert_verify_mean_ms'])} | "
        f"{abort['public_cert_bytes']} |",
        f"| Replay / unattributable abort | "
        f"{f(abort['replay_failure_mean_ms'])} | "
        f"{f(abort['replay_failure_median_ms'])} | "
        f"{f(abort['replay_failure_p95_ms'])} | "
        f"{f(abort['replay_scope_sync_mean_ms'])} | "
        f"{f(abort['replay_batch_check_mean_ms'])} | "
        f"{f(abort['replay_cert_verify_mean_ms'])} | "
        f"{abort['replay_cert_bytes']} |",
        "",
        "## Independent judge",
        "",
        f"- Mean verification: {f(judge['mean_verify_ms'])} ms.",
        f"- P95 verification: {f(judge['p95_verify_ms'])} ms.",
        f"- Canonical certificate: {judge['canonical_certificate_bytes']} bytes.",
        f"- Serialized certificate file: "
        f"{judge['serialized_certificate_bytes']} bytes.",
        "- Correct registry anchor: ACCEPT; wrong anchor: REJECT.",
        "",
        "## No-framing / negative tests",
        "",
        "| Boundary | Case | Result |",
        "|:---|:---|:---|",
    ]
    for row in matrix:
        md.append(
            f"| {row['path']} | {row['case']} | {row['result']} |")
    md += [
        "",
        "The private causal case binds the downstream operation statement "
        "to the faulty upstream predecessor while keeping the downstream "
        "local residual zero. Localization identifies the upstream owner "
        "and rejects downstream framing.",
    ]
    (args.out / "failure_path_evaluation.md").write_text(
        "\n".join(md) + "\n")

    tex = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Failure handling and adjudication cost. Runtime "
        r"certificate bytes are the failure-handler accounting metric; "
        r"the independent Judge row below reports the canonical serialized "
        r"certificate representation separately.}",
        r"\label{tab:pvia-failure-cost}",
        r"\begin{tabular}{lrrrrrrr}",
        r"\toprule",
        r"Path & Mean (ms) & Median (ms) & P95 (ms) & Scope sync (ms) & "
        r"Batch check (ms) & Cert. verify (ms) & Cert. bytes \\",
        r"\midrule",
        (
            "Publicly attributable abort & "
            f"{f(abort['public_failure_mean_ms'])} & "
            f"{f(abort['public_failure_median_ms'])} & "
            f"{f(abort['public_failure_p95_ms'])} & "
            f"{f(abort['public_scope_sync_mean_ms'])} & "
            f"{f(abort['public_batch_check_mean_ms'])} & "
            f"{f(abort['public_cert_verify_mean_ms'])} & "
            f"{abort['public_cert_bytes']} " + r"\\"
        ),
        (
            "Replay / unattributable abort & "
            f"{f(abort['replay_failure_mean_ms'])} & "
            f"{f(abort['replay_failure_median_ms'])} & "
            f"{f(abort['replay_failure_p95_ms'])} & "
            f"{f(abort['replay_scope_sync_mean_ms'])} & "
            f"{f(abort['replay_batch_check_mean_ms'])} & "
            f"{f(abort['replay_cert_verify_mean_ms'])} & "
            f"{abort['replay_cert_bytes']} " + r"\\"
        ),
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table*}",
        "",
    ]
    (args.out / "failure_path_evaluation.tex").write_text(
        "\n".join(tex))

    summary = [
        "PVIA_FAILURE_EVALUATION_BUNDLE: PASS",
        f"abort_repeats={abort['repeats']}",
        f"abort_warmup={abort['warmup']}",
        f"public_failure_mean_ms={abort['public_failure_mean_ms']}",
        f"public_failure_p95_ms={abort['public_failure_p95_ms']}",
        f"replay_failure_mean_ms={abort['replay_failure_mean_ms']}",
        f"replay_failure_p95_ms={abort['replay_failure_p95_ms']}",
        f"judge_batches={judge['batches']}",
        f"judge_inner_repeats={judge['inner_repeats']}",
        f"judge_mean_verify_ms={judge['mean_verify_ms']}",
        f"judge_p95_verify_ms={judge['p95_verify_ms']}",
        f"judge_canonical_certificate_bytes="
        f"{judge['canonical_certificate_bytes']}",
        f"negative_cases={nf['negative_cases']}",
        f"positive_controls={nf['positive_controls']}",
        "causal_downstream_framing=REJECTED",
        "all_negative_tests=PASS",
        f"abort_latency={args.abort_latency.resolve()}",
        f"judge={args.judge.resolve()}",
        f"no_framing={args.no_framing.resolve()}",
    ]
    (args.out / "FAILURE_EVALUATION_SUMMARY.txt").write_text(
        "\n".join(summary) + "\n")
    print("\n".join(summary))

if __name__ == "__main__":
    main()
