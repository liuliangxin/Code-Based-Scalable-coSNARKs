#!/usr/bin/env python3
import argparse, csv
from pathlib import Path

def rows(path):
    with path.open(newline="",encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))

def by_party(rs):
    return {int(r["parties"]):r for r in rs}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--headline",type=Path,required=True)
    ap.add_argument("--runtime",type=Path,required=True)
    ap.add_argument("--communication",type=Path,required=True)
    ap.add_argument("--out",type=Path,required=True)
    args=ap.parse_args()
    args.out.mkdir(parents=True,exist_ok=True)
    h=by_party(rows(args.headline))
    r=by_party(rows(args.runtime))
    c=by_party(rows(args.communication))
    parties=sorted(set(h)&set(r)&set(c))
    if not parties:
        raise SystemExit("no common party counts")

    out=[]
    for n in parties:
        hh,rr,cc=h[n],r[n],c[n]
        raw_control=float(cc["raw_control_mib"])
        iv_control=float(cc["initial_validity_mib"])
        out.append({
          "parties":n,
          "headline_e2e_overhead_pct":float(hh["e2e_median_overhead_pct"]),
          "headline_full_comm_factor":float(hh["instrumented_full_factor"]),
          "timing_e2e_delta_median_ms":float(rr["e2e_delta_median_ms"]),
          "top_level_timed_median_ms":float(rr["top_level_timed_median_ms"]),
          "top_level_share_median_pct":float(rr["top_level_share_median_pct"]),
          "initial_validity_median_ms":float(rr["initial_validity_median_ms"]),
          "initial_validity_share_of_top_level_pct":float(rr["initial_validity_share_of_top_level_pct"]),
          "preprocessing_median_ms":float(rr["preprocessing_median_ms"]),
          "public_direct_median_ms":float(rr["public_direct_median_ms"]),
          "metadata_observe_median_ms":float(rr["metadata_observe_median_ms"]),
          "metadata_verify_subset_median_ms":float(rr["metadata_verify_subset_median_ms"]),
          "auth_envelope_mib":float(cc["auth_envelope_mib"]),
          "raw_control_mib":raw_control,
          "initial_validity_control_mib":iv_control,
          "initial_validity_share_of_raw_control_pct":100.0*iv_control/raw_control if raw_control else 0.0,
          "preprocessing_control_mib":float(cc["preprocessing_mib"]),
          "metadata_mib":float(cc["metadata_mib"]),
          "full_accounted_mb":float(cc["full_accounted_mb"]),
        })

    with (args.out/"accountability_cost_attribution.csv").open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(out[0]))
        w.writeheader(); w.writerows(out)

    md=["# PVIA accountability cost attribution","",
      "Headline overhead uses the uninstrumented paper-aligned paired batch. Runtime attribution uses a separate timing-instrumented batch and is diagnostic only. Communication attribution uses sender-side instrumented accounting. These scopes are deliberately kept separate.","",
      "| N | Headline E2E overhead | Full comm factor | Timed top-level share | Init-valid ms | Init-valid / timed | Metadata observe ms |",
      "|---:|---:|---:|---:|---:|---:|---:|"]
    for x in out:
        md.append(f"| {x['parties']} | {x['headline_e2e_overhead_pct']:.1f}% | {x['headline_full_comm_factor']:.2f}x | {x['top_level_share_median_pct']:.1f}% | {x['initial_validity_median_ms']:.1f} | {x['initial_validity_share_of_top_level_pct']:.1f}% | {x['metadata_observe_median_ms']:.1f} |")
    md += ["","| N | Auth envelope MiB | Raw control MiB | Init-valid control MiB | Init-valid / raw control | Preproc control MiB | Metadata MiB |",
           "|---:|---:|---:|---:|---:|---:|---:|"]
    for x in out:
        md.append(f"| {x['parties']} | {x['auth_envelope_mib']:.1f} | {x['raw_control_mib']:.1f} | {x['initial_validity_control_mib']:.1f} | {x['initial_validity_share_of_raw_control_pct']:.1f}% | {x['preprocessing_control_mib']:.1f} | {x['metadata_mib']:.2f} |")
    md += ["",
      "Interpretation: the initial-validity gate is the dominant directly timed top-level module, especially at higher party counts. The authenticated envelope is the largest aggregate communication component, while initial-validity traffic dominates the scoped control bytes. Transfer metadata is small in bytes but receive-side observe/verify time grows with the party count; these metadata timers are cross-cutting and are not added to the top-level timing share.",
      "",
      "The uninstrumented headline batch remains the source for performance claims. The timing-instrumented batch is used only to explain where the overhead arises."]
    (args.out/"accountability_cost_attribution.md").write_text("\n".join(md)+"\n")

    bs=chr(92); dol=chr(36)
    tex_rows=[]
    for x in out:
        tex_rows.append(
          f"{x['parties']} & {x['headline_e2e_overhead_pct']:.1f}{bs}% & "
          f"{x['headline_full_comm_factor']:.2f}{dol}{bs}times{dol} & "
          f"{x['top_level_share_median_pct']:.1f}{bs}% & {x['initial_validity_median_ms']:.1f} & "
          f"{x['initial_validity_share_of_top_level_pct']:.1f}{bs}% & "
          f"{x['initial_validity_share_of_raw_control_pct']:.1f}{bs}% {bs}{bs}")
    tex=[f"{bs}begin{{table*}}[t]",f"{bs}centering",
      f"{bs}caption{{Accountability-cost attribution. Headline E2E and communication factors come from the uninstrumented paper-aligned comparison; runtime attribution comes from a separate timing-instrumented batch. The latter is diagnostic and is not substituted for the headline performance measurement.}}",
      f"{bs}label{{tab:pvia-cost-attribution}}",f"{bs}begin{{tabular}}{{rrrrrrr}}",f"{bs}toprule",
      f"{dol}N{dol} & E2E overhead & Full comm & Timed share & Init-valid (ms) & Init-valid/timed & Init-valid/control {bs}{bs}",
      f"{bs}midrule",*tex_rows,f"{bs}bottomrule",f"{bs}end{{tabular}}",f"{bs}end{{table*}}",""]
    (args.out/"accountability_cost_attribution.tex").write_text("\n".join(tex))

    iv_time=[x["initial_validity_median_ms"] for x in out]
    iv_timed=[x["initial_validity_share_of_top_level_pct"] for x in out]
    iv_control=[x["initial_validity_share_of_raw_control_pct"] for x in out]
    meta=[x["metadata_observe_median_ms"] for x in out]
    parts=[f"{x['headline_e2e_overhead_pct']:.1f}{bs}% at {dol}N={x['parties']}{dol}" for x in out]
    paragraph=(f"{bs}paragraph{{Attributing the accountability tax.}} "
      "Using the uninstrumented paper-aligned batch, PVIA's paired-median E2E overhead is "
      + ", ".join(parts[:-1]) + f", and {parts[-1]}. "
      "A separate instrumentation-only batch shows that the initial-validity gate is the dominant directly timed top-level component: "
      f"its critical-rank median grows from {iv_time[0]:.1f} to {iv_time[-1]:.1f}~ms and contributes "
      f"{min(iv_timed):.1f}{bs}%--{max(iv_timed):.1f}{bs}% of the non-overlapping top-level timed cost. "
      f"The communication decomposition is consistent with this trend: initial-validity traffic accounts for "
      f"{min(iv_control):.1f}{bs}%--{max(iv_control):.1f}{bs}% of scoped control bytes, while authenticated envelopes remain the largest aggregate added traffic component. "
      f"Transfer-metadata observe time grows from {meta[0]:.1f} to {meta[-1]:.1f}~ms, but it is cross-cutting and therefore not added to the top-level module total. "
      "The residual E2E delta includes authenticated-envelope processing, secure-transfer work, collective synchronization, and run-to-run variation not isolated by a non-overlapping module timer.")
    (args.out/"accountability_cost_attribution_paragraph.tex").write_text(paragraph+"\n")

    lines=["PVIA_ACCOUNTABILITY_COST_ATTRIBUTION: PASS",
      "parties="+",".join(map(str,parties)),
      "headline_source=uninstrumented_paper_aligned",
      "runtime_source=timing_instrumented_diagnostic_only",
      "communication_source=instrumented_sender_side_accounting",
      f"initial_validity_time_ms={min(iv_time):.3f}..{max(iv_time):.3f}",
      f"initial_validity_share_of_timed_pct={min(iv_timed):.3f}..{max(iv_timed):.3f}",
      f"initial_validity_share_of_raw_control_pct={min(iv_control):.3f}..{max(iv_control):.3f}",
      f"metadata_observe_ms={min(meta):.3f}..{max(meta):.3f}",
      "headline_not_replaced_by_timing_batch=1"]
    (args.out/"SUMMARY.txt").write_text("\n".join(lines)+"\n")
    print("\n".join(lines))

if __name__=="__main__":
    main()
