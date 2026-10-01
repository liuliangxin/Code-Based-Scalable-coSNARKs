#!/usr/bin/env python3
import argparse, csv, hashlib, json, os, platform, re, socket, subprocess
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def read_matrix(path: Path):
    with path.open(newline='', encoding='utf-8-sig') as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError('empty regression matrix')
    return rows


def run_text(cmd):
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT).strip()
    except Exception as exc:
        return f'unavailable: {type(exc).__name__}'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, default=Path('.'))
    ap.add_argument('--matrix-dir', type=Path, required=True)
    ap.add_argument('--mode', choices=['regression', 'measurement'], default='regression')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--markdown', type=Path, required=True)
    args = ap.parse_args()

    root = args.root.resolve()
    matrix_dir = args.matrix_dir.resolve()
    rows = read_matrix(matrix_dir / 'regression_matrix.csv')
    pass_rows = [r for r in rows if r['status'] == 'PASS']
    unsupported_rows = [r for r in rows if r['status'] == 'UNSUPPORTED']
    other_rows = [r for r in rows if r['status'] not in {'PASS', 'UNSUPPORTED'}]
    if other_rows:
        raise ValueError(f'unexpected matrix statuses: {sorted({r["status"] for r in other_rows})}')
    if not pass_rows:
        raise ValueError('no passing matrix points')
    control_scope_partition_pass = all(
        int(float(r.get('control_scope_partition_complete', '0'))) == 1 and
        float(r.get('unclassified_control_bytes', '1')) == 0.0
        for r in pass_rows)
    round_scopes = sorted({r.get('round_scope', '') for r in pass_rows})
    communication_scopes = sorted({
        r.get('communication_scope', '') for r in pass_rows})


    consistency_paths = sorted({
        r.get('consistency_path', '') for r in pass_rows})
    if len(consistency_paths) != 1 or consistency_paths[0] not in {
            'reference', 'strong'}:
        raise ValueError(
            f'mixed or invalid consistency paths: {consistency_paths}')


    provider_state_fields = [
        'consistency_provider_present',
        'consistency_provider_production_ready',
        'consistency_provider_acceptance_present',
        'consistency_provider_protocol_id',
        'consistency_provider_active']
    provider_state = {}
    for field in provider_state_fields:
        values = sorted({int(float(r.get(field, '0'))) for r in pass_rows})
        if len(values) != 1:
            raise ValueError(
                f'mixed consistency-provider state for {field}: {values}')
        provider_state[field] = values[0]
    if provider_state['consistency_provider_active'] == 1:
        if (
            provider_state['consistency_provider_present'] != 1 or
            provider_state['consistency_provider_production_ready'] != 1 or
            provider_state['consistency_provider_acceptance_present'] != 1 or
            provider_state['consistency_provider_protocol_id'] <= 0 or
            consistency_paths != ['strong']
        ):
            raise ValueError('incomplete active consistency-provider state')
    else:
        if (
            provider_state['consistency_provider_present'] != 0 or
            provider_state['consistency_provider_production_ready'] != 0 or
            provider_state['consistency_provider_acceptance_present'] != 0 or
            provider_state['consistency_provider_protocol_id'] != 0 or
            consistency_paths != ['reference']
        ):
            raise ValueError('reference path has partial provider state')

    required_logs = ['mapping_preflight.log', 'mapping_postflight.log', 'paper_alignment.log', 'private_epoch_transport.log', 'consistency_backend_readiness.log', 'provider_status_smoke.log', 'provider_relation_vectors.log',
                     'failure_no_framing.log', 'localization_scaling_smoke.log',
                     'release_gate_matrix.log', 'localization_np8_smoke.log', 'build.log', 'collect.log']
    missing = [name for name in required_logs if not (matrix_dir / name).is_file()]
    if missing:
        raise ValueError(f'missing matrix artifacts: {missing}')

    source_paths = [
        Path('src/main.cpp'), Path('src/CMakeLists.txt'),
        Path('src/coPIOP.cpp'), Path('src/coPCS.cpp'), Path('src/coSumcheck_MPI.cpp'),
        Path('src/Distributed_Sumcheck.cpp'), Path('src/MPI_utils.cpp'), Path('src/MPI_utils.hpp'),
        Path('src/accountability/PVIA.cpp'), Path('src/accountability/PVIA.hpp'),
        Path('src/accountability/AuthenticatedMpcExchange.cpp'),
        Path('src/accountability/AuthenticatedMpcExchange.hpp'),
        Path('src/accountability/MultiplicationConsistencyProof.cpp'),
        Path('src/accountability/MultiplicationConsistencyProof.hpp'),
        Path('src/accountability/MultiplicationConsistencySharingWitness.cpp'),
        Path('src/accountability/MultiplicationConsistencySharingWitness.hpp'),
        Path('src/accountability/MultiplicationConsistencyWitnessRelation.cpp'),
        Path('src/accountability/MultiplicationConsistencyWitnessRelation.hpp'),
        Path('src/accountability/ExternalMultiplicationConsistencyProofAdapter.cpp'),
        Path('src/accountability/ExternalMultiplicationConsistencyProofAdapter.hpp'),
        Path('src/accountability/ExternalMultiplicationConsistencyProviderSession.cpp'),
        Path('src/accountability/ExternalMultiplicationConsistencyProviderSession.hpp'),
        Path('src/accountability/MultiplicationConsistencyProviderAbi.cpp'),
        Path('src/accountability/MultiplicationConsistencyProviderAbiC.h'),
        Path('src/accountability/MultiplicationConsistencyProviderRelationReference.h'),
        Path('src/accountability/MultiplicationConsistencyProviderAbiHelpers.h'),
        Path('src/accountability/MultiplicationConsistencyProviderAbi.hpp'),
        Path('src/accountability/SharedLibraryMultiplicationConsistencyProviderSession.cpp'),
        Path('src/accountability/SharedLibraryMultiplicationConsistencyProviderSession.hpp'),
        Path('src/accountability/MultiplicationConsistencyProviderAcceptance.cpp'),
        Path('src/accountability/MultiplicationConsistencyProviderAcceptance.hpp'),
        Path('src/accountability/MultiplicationConsistencyBackendRegistry.hpp'),
        Path('src/accountability/ReferenceLinearSharingProvenance.cpp'),
        Path('src/accountability/ReferenceLinearSharingProvenance.hpp'),
        Path('src/accountability/SecureAuditComposition.cpp'),
        Path('src/accountability/SecureAuditComposition.hpp'),
        Path('src/accountability/InitialValidityGate.cpp'),
        Path('src/accountability/InitialValidityGate.hpp'),
        Path('src/accountability/JointPackedPreprocessing.cpp'),
        Path('src/accountability/JointPackedPreprocessing.hpp'),
        Path('src/accountability/ProtocolTrafficMetrics.hpp'),
        Path('src/accountability/PublicDirectValidation.cpp'),
        Path('src/accountability/PublicDirectValidation.hpp'),
        Path('src/accountability/ExperimentMetrics.cpp'),
        Path('src/accountability/ExperimentMetrics.hpp'),
        Path('src/accountability/ReferenceShamirMpc.cpp'),
        Path('src/accountability/ReferenceBivariateVss.cpp'),
        Path('src/accountability/ReferenceShamirMpc.hpp'),
        Path('src/accountability/ReferenceBivariateVss.hpp'),
        Path('src/accountability/AttestedResidualRuntimeBundle.cpp'),
        Path('src/accountability/AttestedResidualRuntimeBundle.hpp'),
        Path('src/accountability/ReferenceResidualMpcSelfTest.cpp'),
        Path('src/accountability/Ed25519TransferAuditHarness.cpp'),
        Path('src/accountability/Ed25519TransferAuditHarness.hpp'),
        Path('experiments/run_failure_no_framing_matrix_xfusion.sh'),
        Path('experiments/build_failure_evaluation_bundle.py'),
        Path('experiments/run_localization_scaling_xfusion.sh'),
        Path('experiments/build_localization_evaluation_bundle.py'),
        Path('experiments/run_pappas_aligned_accountability_xfusion.sh'),
        Path('experiments/build_baseline_accountability_comparison.py'),
        Path('experiments/build_accountability_tax_evaluation.py'),
        Path('src/accountability/ReleaseGateMatrixSelfTest.cpp'),
        Path('src/accountability/ReleaseGateMatrixSelfTest.hpp'),
        Path('experiments/run_release_gate_matrix_xfusion.sh'),
        Path('experiments/run_localization_party_scaling_xfusion.sh'),
        Path('experiments/aggregate_pvia_metrics.py'),
        Path('experiments/run_copiop_overhead_xfusion.sh'),
        Path('experiments/run_copiop_regression_matrix_xfusion.sh'),
        Path('experiments/run_copiop_green_gate_xfusion.sh'),
        Path('experiments/run_copiop_short_preflight_xfusion.sh'),
        Path('experiments/collect_copiop_regression_matrix.py'),
        Path('experiments/build_evaluation_tables.py'),
        Path('experiments/build_pvia_evaluation_bundle.py'),
        Path('notes/PVIA_EVALUATION_SCOPE.md'),
        Path('experiments/start_detached_task.sh'),
        Path('experiments/task_status.sh'),
        Path('experiments/check_private_epoch_transport_coverage.py'),
        Path('experiments/check_consistency_backend_readiness.py'),
        Path('experiments/run_consistency_provider_status_smoke_xfusion.sh'),
        Path('experiments/check_provider_relation_vectors.py'),
        Path('experiments/run_provider_relation_vector_export_xfusion.sh'),
        Path('experiments/run_provider_candidate_acceptance_xfusion.sh'),
        Path('experiments/check_experiment_metrics_protocol_id.py'),
        Path('experiments/check_experiment_control_scope_partition.py'),
        Path('experiments/check_experiment_peak_rss.py'),
        Path('experiments/check_sp1_candidate_runtime_evidence.py'),
        Path('experiments/finalize_sp1_candidate_alignment.py'),
        Path('experiments/build_provider_sdk_bundle.py'),
        Path('experiments/sp1_provider/Cargo.toml'),
        Path('experiments/sp1_provider/relation/Cargo.toml'),
        Path('experiments/sp1_provider/relation/src/lib.rs'),
        Path('experiments/sp1_provider/relation/examples/check_vectors.rs'),
        Path('experiments/sp1_provider/program/Cargo.toml'),
        Path('experiments/sp1_provider/program/src/main.rs'),
        Path('experiments/sp1_provider/host/Cargo.toml'),
        Path('experiments/sp1_provider/host/src/lib.rs'),
        Path('experiments/sp1_provider/host/examples/execute_vector.rs'),
        Path('experiments/sp1_provider/host/examples/check_vector.rs'),
        Path('experiments/sp1_provider/host/examples/prove_vector.rs'),
        Path('experiments/sp1_provider/host/examples/prove_provider_vector.rs'),
        Path('experiments/sp1_provider/artifacts/pvia-sp1-relation-program'),
        Path('experiments/run_sp1_provider_e2e_xfusion.sh'),
        Path('experiments/run_sp1_provider_stage_probe_xfusion.sh'),
        Path('experiments/build_sp1_groth16_candidate_xfusion.sh'),
        Path('experiments/run_sp1_groth16_candidate_cabi_xfusion.sh'),
        Path('experiments/sp1_provider/check_c_abi_artifact.py'),
        Path('experiments/sp1_provider/evidence/groth16_privacy_evidence.txt'),
        Path('experiments/sp1_provider/elf/pvia-sp1-relation-program'),
        Path('notes/SP1_GROTH16_PRIVACY_EVIDENCE.md'),
        Path('experiments/sp1_provider/check_dev_cabi.c'),
        Path('experiments/run_sp1_provider_dev_cabi_xfusion.sh'),
        Path('experiments/provider_fixtures/pvia_mc_provider_abi_mismatch.c'),
        Path('experiments/provider_fixtures/pvia_mc_provider_unready.c'),
        Path('experiments/provider_sdk/ProviderTemplate.c'),
        Path('experiments/provider_sdk/MultiplicationConsistencyProviderRelationReference.h'),
        Path('experiments/provider_sdk/MultiplicationConsistencyProviderRelationReference.c'),
        Path('experiments/provider_fixtures/pvia_mc_provider_relation_mismatch.c'),
        Path('experiments/provider_fixtures/pvia_mc_provider_conformance_only.c'),
        Path('notes/PAPPAS_PROTOCOL_CODE_MAP.csv'),
        Path('notes/PVIA_PRIVATE_EPOCH_TRANSPORT_MAP.csv'),
        Path('notes/SP1_PROVIDER_MODE_EVIDENCE.md'),
        Path('notes/PAPPAS_CODE_RELEASE_MANIFEST.md'),
        Path('notes/PVIA_PAPER_IMPLEMENTATION_ALIGNMENT.csv'),
    ]
    source_hashes = {}
    for rel in source_paths:
        path = root / rel
        if not path.is_file():
            raise ValueError(f'missing source artifact: {rel}')
        source_hashes[str(rel)] = sha256(path)

    binary = root / 'build-pvia/src/pigeon'
    alignment_text = (matrix_dir / 'paper_alignment.log').read_text(errors='ignore')
    alignment_match = re.search(
        r'PAPER_IMPLEMENTATION_ALIGNMENT: PASS implemented=(\d+) partial=(\d+) open=(\d+)',
        alignment_text)
    alignment_counts = {
        'implemented': int(alignment_match.group(1)) if alignment_match else None,
        'partial': int(alignment_match.group(2)) if alignment_match else None,
        'open': int(alignment_match.group(3)) if alignment_match else None,
    }
    transport_text = (
        matrix_dir / 'private_epoch_transport.log').read_text(errors='ignore')
    transport_match = re.search(
        r'PRIVATE_EPOCH_TRANSPORT_COVERAGE: PASS implemented=(\d+) partial=(\d+) out_of_scope=(\d+)',
        transport_text)
    transport_counts = {
        'implemented': int(transport_match.group(1))
            if transport_match else None,
        'partial': int(transport_match.group(2))
            if transport_match else None,
        'out_of_scope': int(transport_match.group(3))
            if transport_match else None,
    }

    consistency_text = (
        matrix_dir / 'consistency_backend_readiness.log').read_text(
            errors='ignore')
    consistency_line = next(
        (line for line in consistency_text.splitlines()
         if line.startswith('CONSISTENCY_BACKEND_READINESS:')),
        'CONSISTENCY_BACKEND_READINESS: UNKNOWN')
    consistency_backend_ready = consistency_line.startswith(
        'CONSISTENCY_BACKEND_READINESS: READY')
    provider_smoke_text = (
        matrix_dir / 'provider_status_smoke.log').read_text(errors='ignore')
    provider_status_smoke_pass = (
        'CONSISTENCY_PROVIDER_STATUS_SMOKE: PASS' in provider_smoke_text)
    provider_vector_text = (
        matrix_dir / 'provider_relation_vectors.log').read_text(errors='ignore')
    provider_relation_vectors_pass = (
        'PROVIDER_RELATION_VECTOR_EXPORT: PASS' in provider_vector_text and
        'PROVIDER_RELATION_VECTORS: PASS' in provider_vector_text)

    failure_no_framing_text = (
        matrix_dir / 'failure_no_framing.log').read_text(errors='ignore')
    failure_no_framing_pass = (
        'PVIA FAILURE NO-FRAMING MATRIX: PASS' in failure_no_framing_text and
        'wrong_session=REJECTED' in failure_no_framing_text and
        'certificate_tamper=REJECTED' in failure_no_framing_text and
        'proof_tamper=REJECTED' in failure_no_framing_text and
        'wrong_registry_anchor=REJECTED' in failure_no_framing_text and
        'causal_upstream_localization=UPSTREAM' in failure_no_framing_text and
        'downstream_framing=REJECTED' in failure_no_framing_text)

    localization_smoke_text = (
        matrix_dir / 'localization_scaling_smoke.log').read_text(
            errors='ignore')
    localization_scaling_smoke_pass = (
        'PVIA LOCALIZATION SCALING: PASS' in localization_smoke_text and
        'q8_first_depth=3' in localization_smoke_text and
        'q8_first_subset_checks=3' in localization_smoke_text and
        'q8_last_depth=3' in localization_smoke_text and
        'q8_last_subset_checks=6' in localization_smoke_text)

    release_gate_text = (
        matrix_dir / 'release_gate_matrix.log').read_text(errors='ignore')
    release_gate_matrix_pass = (
        'PVIA RELEASE GATE MATRIX: PASS' in release_gate_text and
        'cosumcheck_injected=WITHHOLD' in release_gate_text and
        'distributed_sumcheck_injected=WITHHOLD' in release_gate_text and
        'encoding_injected=WITHHOLD' in release_gate_text and
        'pcs_open_injected=WITHHOLD' in release_gate_text and
        'pcs_batch_open_injected=WITHHOLD' in release_gate_text and
        'exact_scope=BOUND' in release_gate_text and
        'claim_scope=release-gate-withholding-semantics' in release_gate_text)

    localization_np8_text = (
        matrix_dir / 'localization_np8_smoke.log').read_text(errors='ignore')
    localization_np8_smoke_pass = (
        'PVIA LOCALIZATION SCALING: PASS' in localization_np8_text and
        'np=8' in localization_np8_text and
        'q32_first_depth=5' in localization_np8_text and
        'q32_last_depth=5' in localization_np8_text)

    checkpoint = {
        'schema': 'copiop-green-checkpoint-v1',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'mode': args.mode,
        'host': socket.gethostname(),
        'platform': platform.platform(),
        'compiler': run_text(['c++', '--version']).splitlines()[0],
        'matrix_dir': str(matrix_dir),
        'matrix_points': len(rows),
        'pass_points': len(pass_rows),
        'unsupported_points': len(unsupported_rows),
        'parties': sorted({int(r['parties']) for r in rows}),
        'm_log_values': sorted({int(r['m_log']) for r in rows}),
        'pass_coordinates': [[int(r['parties']), int(r['m_log'])] for r in pass_rows],
        'unsupported_coordinates': [[int(r['parties']), int(r['m_log'])] for r in unsupported_rows],
        'mapping_preflight_pass': 'PROTOCOL_CODE_MAPPING: PASS' in (matrix_dir / 'mapping_preflight.log').read_text(errors='ignore'),
        'mapping_postflight_pass': 'PROTOCOL_CODE_MAPPING: PASS' in (matrix_dir / 'mapping_postflight.log').read_text(errors='ignore'),
        'collector_pass': 'COPIOP_REGRESSION_MATRIX_COLLECT: PASS' in (matrix_dir / 'collect.log').read_text(errors='ignore'),
        'paper_alignment_pass': 'PAPER_IMPLEMENTATION_ALIGNMENT: PASS' in alignment_text,
        'paper_alignment_counts': alignment_counts,
        'private_epoch_transport_pass':
            'PRIVATE_EPOCH_TRANSPORT_COVERAGE: PASS' in transport_text,
        'private_epoch_transport_counts': transport_counts,
        'consistency_backend_readiness': consistency_line,
        'consistency_backend_ready': consistency_backend_ready,
        'provider_status_smoke_pass': provider_status_smoke_pass,
        'provider_relation_vectors_pass': provider_relation_vectors_pass,
        'failure_no_framing_pass': failure_no_framing_pass,
        'localization_scaling_smoke_pass': localization_scaling_smoke_pass,
        'release_gate_matrix_pass': release_gate_matrix_pass,
        'localization_np8_smoke_pass': localization_np8_smoke_pass,
        'consistency_provider_state': provider_state,
        'production_backend_active': (
            provider_state['consistency_provider_active'] == 1 and
            consistency_paths == ['strong']),
        'control_scope_partition_pass': control_scope_partition_pass,
        'round_scopes': round_scopes,
        'communication_scopes': communication_scopes,
        'consistency_paths': consistency_paths,
        'binary_sha256': sha256(binary) if binary.is_file() else None,
        'source_sha256': source_hashes,
    }
    checkpoint['green'] = all([
        checkpoint['mapping_preflight_pass'], checkpoint['mapping_postflight_pass'],
        checkpoint['collector_pass'], checkpoint['paper_alignment_pass'],
        checkpoint['private_epoch_transport_pass'],
        checkpoint['consistency_backend_ready'],
        checkpoint['provider_status_smoke_pass'],
        checkpoint['provider_relation_vectors_pass'],
        checkpoint['failure_no_framing_pass'],
        checkpoint['localization_scaling_smoke_pass'],
        checkpoint['release_gate_matrix_pass'],
        checkpoint['localization_np8_smoke_pass'],
        checkpoint['control_scope_partition_pass'], checkpoint['pass_points'] > 0,
    ])
    if not checkpoint['green']:
        raise SystemExit('checkpoint prerequisites are not green')

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(checkpoint, indent=2, sort_keys=True) + '\n', encoding='utf-8')

    lines = [
        '# coPIOP Green Checkpoint', '',
        f"- Status: **GREEN**",
        f"- Created (UTC): `{checkpoint['created_utc']}`",
        f"- Mode: `{checkpoint['mode']}`",
        f"- Matrix: {checkpoint['pass_points']} PASS, {checkpoint['unsupported_points']} UNSUPPORTED, {checkpoint['matrix_points']} total",
        f"- Parties: {checkpoint['parties']}",
        f"- M_LOG values: {checkpoint['m_log_values']}",
        f"- Protocol/code mapping: preflight PASS, postflight PASS",
        f"- Paper/implementation alignment: PASS ({alignment_counts['implemented']} IMPLEMENTED, {alignment_counts['partial']} PARTIAL, {alignment_counts['open']} OPEN)",
        f"- Private-epoch transport coverage: PASS ({transport_counts['implemented']} IMPLEMENTED, {transport_counts['partial']} PARTIAL, {transport_counts['out_of_scope']} OUT_OF_SCOPE)",
        f"- Consistency backend readiness: {consistency_line.replace('CONSISTENCY_BACKEND_READINESS: ', '')}",
        f"- Provider activation smoke: {'PASS' if checkpoint['provider_status_smoke_pass'] else 'FAIL'}",
        f"- Provider relation vectors: {'PASS' if checkpoint['provider_relation_vectors_pass'] else 'FAIL'}",
        f"- Failure/no-framing regression: {'PASS' if checkpoint['failure_no_framing_pass'] else 'FAIL'}",
        f"- Localization-scaling smoke: {'PASS' if checkpoint['localization_scaling_smoke_pass'] else 'FAIL'}",
        f"- Release-gate withholding matrix: {'PASS' if checkpoint['release_gate_matrix_pass'] else 'FAIL'}",
        f"- Runtime consistency provider: {'accepted' if checkpoint['production_backend_active'] else 'none'} (protocol_id={provider_state['consistency_provider_protocol_id']})",
        f"- Control-scope partition: PASS (zero unclassified bytes on all PASS points)",
        f"- Round scope: {checkpoint['round_scopes']}",
        f"- Communication scope: {checkpoint['communication_scopes']}",
        f"- Consistency path: {checkpoint['consistency_paths'][0]}",
        f"- Binary SHA-256: `{checkpoint['binary_sha256']}`", '',
        'This checkpoint certifies the implemented normal-path regression, protocol-to-code mapping, '
        'failure/no-framing regression, and evidence-bound production-backend readiness. '
        'The external SP1 production provider remains '
        'an explicit accepted shared-library activation rather than a default built-in backend.',
        ''
    ]
    args.markdown.write_text('\n'.join(lines), encoding='utf-8')
    print('COPIOP_GREEN_CHECKPOINT: PASS')
    print(args.output)
    print(args.markdown)

if __name__ == '__main__':
    main()
