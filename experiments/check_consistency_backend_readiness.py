#!/usr/bin/env python3
import argparse
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path

STRUCTURAL_REQUIREMENTS = {
    'experiments/sp1_provider/Cargo.toml': [
        'members = ["relation", "program", "host"]',
    ],
    'experiments/sp1_provider/relation/Cargo.toml': [
        'name = "pvia-mc-relation"',
        'blake3',
        'serde',
    ],
    'experiments/sp1_provider/relation/src/lib.rs': [
        'pub fn relation_binding()',
        'pub fn validate_relation(',
        'pub fn evaluate(',
        'VSS_TRANSCRIPT_DOMAIN',
        'LINEAR_BINDING_DOMAIN',
        'validate_vss_local(',
        'validate_vss_dealer(',
        'validate_linear(',
    ],
    'experiments/sp1_provider/relation/examples/check_vectors.rs': [
        'RUST_RELATION_VECTORS: PASS',
        'validate_relation(&statement, &witness)',
        'relation_binding() != expected_relation',
    ],
    'experiments/sp1_provider/program/Cargo.toml': [
        'sp1-zkvm = { version = "=6.8.1" }',
        'pvia-mc-relation = { path = "../relation" }',
    ],
    'experiments/sp1_provider/program/src/main.rs': [
        'sp1_zkvm::entrypoint!(main)',
        'evaluate(&input)',
        'sp1_zkvm::io::commit(&public_values)',
    ],
    'experiments/sp1_provider/host/Cargo.toml': [
        'crate-type = ["cdylib", "rlib"]',
        'sp1-sdk = { version = "=6.8.1", features = ["blocking"] }',
        'pvia-mc-relation = { path = "../relation" }',
        'bincode = "1.3.3"',
        'blake3 = "1.8.2"',
        'groth16-candidate = []',
    ],
    'experiments/sp1_provider/host/src/lib.rs': [
        'pvia_mc_provider_abi_version',
        'pvia_mc_provider_capabilities',
        'pvia_mc_provider_prove',
        'pvia_mc_provider_verify',
        'PVIA_SP1_PROOF_SYSTEM_ID: u32 = 68_101',
        'PVIA_SP1_PROTOCOL_ID',
        'const DEFAULT_PRODUCTION_PRIVACY_CONFIRMED: bool = false;',
        '#[cfg(feature = "groth16-candidate")]',
        'const PRODUCTION_PRIVACY_CONFIRMED: bool = true;',
        'include_bytes!("../../elf/pvia-sp1-relation-program")',
        'pub fn execute_relation(',
        'pub fn prove_core_relation(',
        'pub fn prove_groth16_relation(',
        'pub fn prove_provider_relation(',
        'pub fn provider_proof_mode_name()',
        'PVIA_SP1_PROVIDER_PROOF_MODE: &str = "groth16"',
        'pub fn verify_sp1_relation_proof(',
        '.groth16()',
        'PROOF_CACHE',
        'if inout_proof_word_count.is_null() || !PRODUCTION_PRIVACY_CONFIRMED',
        'if !PRODUCTION_PRIVACY_CONFIRMED',
    ],
    'experiments/sp1_provider/host/examples/execute_vector.rs': [
        'SP1_RELATION_EXECUTION: PASS',
        'execute_relation(&statement, &witness)',
    ],
    'experiments/sp1_provider/host/examples/prove_vector.rs': [
        'SP1_RELATION_CORE_PROOF: PASS',
        'prove_core_relation(&statement, &witness)',
        'verify_sp1_relation_proof(&statement, &proof)',
    ],
    'experiments/sp1_provider/host/examples/prove_provider_vector.rs': [
        'SP1_RELATION_PROVIDER_PROOF: PASS',
        'prove_provider_relation(&statement, &witness)',
        'provider_proof_mode_name()',
        'verify_sp1_relation_proof(&statement, &proof)',
    ],
    'experiments/sp1_provider/host/examples/prove_measure_vector.rs': [
        'SP1_CORE_PROVE_VECTOR: PASS',
        'prove_core_relation(&statement, &witness)',
        'verify_sp1_relation_proof(&statement, &proof)',
    ],
    'experiments/sp1_provider/check_dev_cabi.c': [
        'SP1_PROVIDER_DEV_C_ABI: PASS',
        'PVIA_MC_CAP_ZERO_KNOWLEDGE_INDEX',
        'pvia_mc_reference_capability_binding(',
    ],
    'experiments/run_sp1_provider_dev_cabi_xfusion.sh': [
        'check_dev_cabi.c',
        'libpvia_sp1_provider_host.so',
    ],
    'experiments/run_sp1_provider_stage_probe_xfusion.sh': [
        'SP1_PROVIDER_STAGE_PROBE: PASS',
        'PROOF_SYSTEM_ID=68101',
        'proof_mode=groth16',
        'privacy_capability=0',
        'provider_probe_rc',
        'production_ready=0',
        'host_sha256=',
        'library_sha256=',
    ],
    'experiments/build_sp1_groth16_candidate_xfusion.sh': [
        'SP1_GROTH16_CANDIDATE_BUILD: PASS',
        '--features groth16-candidate',
        'candidate_privacy_capability=1',
        'default_privacy_capability=0',
        'default_restore.log',
    ],
    'experiments/sp1_provider/evidence/groth16_privacy_evidence.txt': [
        'SP1_GROTH16_PRIVACY_EVIDENCE: PASS',
        'sp1_version=6.8.1',
        'proof_mode=groth16',
        'sp1_gnark_replace=github.com/p4u/gnark@cd7874155e266e08ca8dc247dbc66efb1030bd3b',
        'gnark_randomization=_r.SetRandom(),_s.SetRandom()',
        'gnark_crypto_random_source=crypto/rand.Reader',
        'guest_public_values=abi_version,relation_binding,statement_binding',
    ],
    'experiments/run_sp1_groth16_candidate_cabi_xfusion.sh': [
        'SP1_GROTH16_CANDIDATE_C_ABI: PASS',
        'SP1_C_ABI_PROVE: PASS',
        'SP1_C_ABI_VERIFY: PASS',
        '--expected-zero-knowledge 1',
        'candidate_library_sha256',
    ],
    'notes/SP1_PROVIDER_MODE_EVIDENCE.md': [
        'SP1 SDK / zkVM version: 6.8.1',
        'github.com/p4u/gnark commit cd7874155e26',
        '41810928d73b2d099129370f5e43575c6344b458',
        'groth16.Prove(globalR1cs, globalPk, witness)',
        'SetRandom',
        'The default provider remains fail-closed.',
    ],
    'experiments/run_sp1_provider_e2e_xfusion.sh': [
        'RUST_RELATION_VECTORS: PASS',
        'SP1_RELATION_EXECUTION: PASS',
        'SP1_RELATION_PROVIDER_PROOF: PASS',
        'SP1_PROVIDER_E2E_DEVELOPMENT: PASS',
        'proof_mode=groth16',
        'privacy_capability=0',
        'host_sha256=',
        'library_sha256=',
    ],
    'src/accountability/MultiplicationConsistencyBackendRegistry.hpp': [
        'production_ready_multiplication_consistency_capabilities',
        'AcceptanceMatches(',
        'InstallAccepted(',
        'CurrentAcceptanceBinding()',
        'ScopedMultiplicationConsistencyBackendRegistration',
    ],
    'src/accountability/AttestedResidualRuntimeBundle.cpp': [
        'MultiplicationConsistencyBackendRegistry::Current()',
        'MultiplicationConsistencyBackendRegistry::AcceptanceMatches(',
        'consistency_acceptance',
        'consistency_registration_(',
    ],
    'src/accountability/ReferenceShamirAuditSession.cpp': [
        'MultiplicationConsistencyProviderRelationReference.h',
        'pvia_mc_reference_validate_relation(',
        'relation_reference_count()',
        'vss_local_prove_count()',
        'linear_prove_count()',
        'multiplication_backend.linear_prove_count() > 0',
        'backend.vss_local_prove_count() > 0',
    ],
    'src/accountability/InitialValidityGate.cpp': [
        'MultiplicationConsistencyBackendRegistry::Current()',
        'MultiplicationConsistencyBackendRegistry::CurrentAcceptanceBinding()',
        'ShareLocalSumWithProvenance(',
        'MaskedZeroTestWithConsistency(',
        'strong_consistency_used',
        'consistency_acceptance_binding',
        'experiment_record_consistency_provider_status(',
        'multiplication_consistency_binding',
    ],
    'src/accountability/ReferenceShamirMpc.cpp': [
        'production_ready_multiplication_consistency_capabilities(',
        'AUTH_KIND_PROOF_BROADCAST',
        'AUTH_KIND_VERIFY_AGREEMENT',
        'compute_multiplication_consistency_set_binding(',
        'CollectiveSameDigest(proof_set_binding',
        'ShareLocalSumWithProvenance(',
    ],
    'src/accountability/MultiplicationConsistencyProof.cpp': [
        'PVIA_MC_PROOF_COMMITMENT_DOMAIN',
        'PVIA_MC_CAPABILITY_BINDING_DOMAIN',
        'validate_multiplication_consistency_proof_artifact(',
        'production_ready_multiplication_consistency_capabilities(',
        'FailClosedMultiplicationConsistencyProofBackend::Capabilities()',
    ],
    'src/accountability/ExternalMultiplicationConsistencyProofAdapter.cpp': [
        'expected_proof_system_id_ != 0',
        'proof.proof_system_id != expected_proof_system_id_',
        'proof.proof_system_id == expected_proof_system_id_',
    ],
    'src/accountability/ExternalMultiplicationConsistencyProviderSession.cpp': [
        'run_multiplication_consistency_provider_acceptance(',
        'ScopedMultiplicationConsistencyBackendRegistration',
        'CurrentAcceptanceBinding()',
        'registration->active()',
    ],
    'src/accountability/ExperimentMetrics.cpp': [
        'experiment_record_consistency_provider_status(',
        'consistency_provider_present',
        'consistency_provider_production_ready',
        'consistency_provider_acceptance_present',
        'consistency_provider_protocol_id',
    ],
    'src/accountability/MultiplicationConsistencyProviderAbiC.h': [
        'PVIA_MC_ABI_VERSION UINT32_C(2)',
        'PVIA_MC_RELATION_BINDING_DOMAIN',
        'PVIA_MC_RELATION_DESCRIPTOR_WORDS',
        'PVIA_MC_CAP_RELATION_BINDING_INDEX',
        'PVIA_MC_STATEMENT_ABI_DOMAIN',
        'PVIA_MC_STATEMENT_BINDING_DOMAIN',
        'PVIA_MC_WITNESS_ABI_DOMAIN',
        'PVIA_MC_CAPABILITY_ABI_DOMAIN',
        'PVIA_MC_PROOF_COMMITMENT_DOMAIN',
        'PVIA_MC_VSS_TRANSCRIPT_DOMAIN',
        'PVIA_MC_LINEAR_BINDING_DOMAIN',
        'PVIA_MC_SHARING_WITNESS_DOMAIN',
        'PVIA_MC_SHARING_KIND_VSS_LOCAL',
        'PVIA_MC_SHARING_KIND_LINEAR_COMBINATION',
        'PVIA_MC_SHARING_KIND_VSS_DEALER',
        'PVIA_MC_ABI_PROVE_SYMBOL_NAME',
        'PVIA_MC_FIELD_MODULUS',
        'pvia_mc_field_mul(',
        'pvia_mc_provider_prove(',
        'pvia_mc_provider_verify(',
    ],
    'src/accountability/MultiplicationConsistencyProviderAbi.hpp': [
        'MultiplicationConsistencyProviderAbiC.h',
        'PVIA_MC_ABI_VERSION',
        'PVIA_MC_ABI_PROVE_SYMBOL_NAME',
    ],
    'src/accountability/MultiplicationConsistencyProviderAbiHelpers.h': [
        'pvia_mc_relation_descriptor_words(',
        'pvia_mc_parse_statement(',
        'pvia_mc_parse_witness(',
        'pvia_mc_parse_sharing_witness(',
        'pvia_mc_parse_vss_local(',
        'pvia_mc_parse_vss_dealer(',
        'pvia_mc_parse_linear(',
        'pvia_mc_linear_source_next(',
        'pvia_mc_validate_witness_payloads(',
    ],
    'src/accountability/MultiplicationConsistencyProviderRelationReference.h': [
        'pvia_mc_reference_relation_binding(',
        'pvia_mc_reference_capability_binding(',
        'pvia_mc_reference_write_capabilities(',
        'pvia_mc_reference_proof_commitment(',
        'pvia_mc_reference_write_proof_artifact(',
        'pvia_mc_reference_validate_vss_local(',
        'pvia_mc_reference_validate_vss_dealer(',
        'pvia_mc_reference_validate_linear(',
        'pvia_mc_reference_statement_binding(',
        'pvia_mc_reference_validate_relation(',
        'PVIA_MC_VSS_TRANSCRIPT_DOMAIN',
        'PVIA_MC_LINEAR_BINDING_DOMAIN',
    ],
    'src/accountability/MultiplicationConsistencyProviderAbi.cpp': [
        'PVIA_MC_STATEMENT_ABI_DOMAIN',
        'PVIA_MC_WITNESS_ABI_DOMAIN',
        'PVIA_MC_CAPABILITY_ABI_DOMAIN',
        'PVIA_MC_STATEMENT_WORDS',
        'PVIA_MC_CAPABILITY_WORDS',
        'encode_multiplication_consistency_statement_abi(',
        'decode_multiplication_consistency_witness_abi(',
        'decode_multiplication_consistency_capabilities_abi(',
    ],
    'src/accountability/SharedLibraryMultiplicationConsistencyProviderSession.cpp': [
        'dlopen(',
        'MULTIPLICATION_CONSISTENCY_ABI_VERSION_SYMBOL',
        'CollectiveProviderAgreement(',
        'capabilities_.relation_binding',
        'MPI_Allreduce(',
        'session_->Activate(',
        'pvia_mc_parse_statement(',
        'pvia_mc_parse_witness(',
        'pvia_mc_validate_witness_payloads(',
    ],
    'src/accountability/SharedLibraryMultiplicationConsistencyProviderSession.hpp': [
        'acceptance() const',
        'session_->acceptance()',
    ],
    'src/accountability/ReferenceBivariateVss.cpp': [
        'compute_reference_vss_transcript_binding(',
        'transcript_context.row_commitments',
        'transcript_context.transport_bindings',
        'PVIA_MC_VSS_TRANSCRIPT_DOMAIN',
        'PVIA_MC_VSS_LOCAL_FIXED_WORDS',
        'PVIA_MC_VSS_DEALER_FIXED_WORDS',
    ],
    'src/accountability/MultiplicationConsistencySharingWitness.cpp': [
        'PVIA_MC_SHARING_WITNESS_DOMAIN',
        'decode_multiplication_consistency_sharing_witness(',
        'wrap_reference_multiplication_consistency_input_sharing_witness(',
        'LINEAR_COMBINATION',
        'VSS_DEALER',
    ],
    'src/accountability/MultiplicationConsistencyWitnessRelation.cpp': [
        'validate_multiplication_consistency_provider_witness_relation(',
        'input_local_share(',
        'output_product_value(',
        'output_value == lhs_share * rhs_share',
    ],
    'src/accountability/ExternalMultiplicationConsistencyProofAdapter.cpp': [
        'validate_multiplication_consistency_provider_witness_relation(',
        'encode_multiplication_consistency_statement_abi(',
        'encode_multiplication_consistency_witness_abi(',
        'pvia_mc_parse_statement(',
        'pvia_mc_parse_witness(',
        'pvia_mc_validate_witness_payloads(',
        'callbacks_.prove(statement, witness)',
        'callbacks_.verify(statement, proof)',
    ],
    'src/main.cpp': [
        'PVIA_MC_PROVIDER_LIBRARY',
        'PVIA_MC_PROVIDER_PROOF_SYSTEM_ID',
        'SharedLibraryMultiplicationConsistencyProviderSession',
        'consistency_provider_session->Activate(',
        'benchmark == 7',
        'consistency-provider-probe',
        'return 19',
    ],
    'src/CMakeLists.txt': [
        'CMAKE_DL_LIBS',
    ],
    'src/fieldElement.cpp': [
        '2305843009213693951LL',
    ],
    'src/accountability/MultiplicationConsistencyProviderAcceptance.cpp': [
        'MultiplyWithConsistency(',
        'MaskedZeroTestWithConsistency(',
        'zero_case_verified',
        'nonzero_case_verified',
        'acceptance_binding',
    ],
    'experiments/aggregate_pvia_metrics.py': [
        'CONSENSUS_STATE_FIELDS',
        'consistency_provider_present',
        'consistency_provider_production_ready',
        'consistency_provider_acceptance_present',
        'consistency_provider_protocol_id',
        'differs by rank',
    ],
    'experiments/run_copiop_overhead_xfusion.sh': [
        'enabled_consistency_provider_present',
        'enabled_consistency_provider_production_ready',
        'enabled_consistency_provider_acceptance_present',
        'enabled_consistency_provider_protocol_id',
        'enabled_consistency_provider_active',
        'RESUME=',
        'reused completed case',
    ],
    'experiments/collect_copiop_regression_matrix.py': [
        'consistency_provider_present',
        'consistency_provider_production_ready',
        'consistency_provider_acceptance_present',
        'consistency_provider_protocol_id',
        'consistency_provider_active',
    ],
    'experiments/create_green_checkpoint.py': [
        'consistency_provider_state',
        'production_backend_active',
        'consistency_provider_active',
    ],
    'experiments/build_evaluation_tables.py': [
        'consistency_provider_active',
        'provider_active',
    ],
    'experiments/run_consistency_provider_status_smoke_xfusion.sh': [
        'run_probe_expect',
        'probe_unconfigured 19',
        'incomplete_configuration 17',
        'abi_version_mismatch 18',
        'relation_binding_mismatch 18',
        'capability_not_ready 18',
        'conformance_only 18',
        'unavailable_library 18',
        'CONSISTENCY_PROVIDER_STATUS_SMOKE: PASS',
    ],
    'experiments/provider_fixtures/pvia_mc_provider_abi_mismatch.c': [
        'MultiplicationConsistencyProviderAbiC.h',
        'PVIA_MC_ABI_VERSION + UINT32_C(1)',
    ],
    'experiments/provider_fixtures/pvia_mc_provider_unready.c': [
        'MultiplicationConsistencyProviderAbiC.h',
        'PVIA_MC_CAPABILITY_ABI_DOMAIN',
        'PVIA_MC_CAPABILITY_WORDS',
    ],
    'experiments/provider_fixtures/pvia_mc_provider_relation_mismatch.c': [
        'MultiplicationConsistencyProviderAbiC.h',
        'PVIA_MC_CAP_RELATION_BINDING_INDEX',
        'PVIA_MC_CAPABILITY_WORDS',
    ],
    'experiments/provider_fixtures/pvia_mc_provider_conformance_only.c': [
        'MultiplicationConsistencyProviderAbiHelpers.h',
        'MultiplicationConsistencyProviderRelationReference.h',
        'pvia_mc_reference_write_capabilities(',
        'pvia_mc_reference_validate_relation(',
        'pvia_mc_reference_write_proof_artifact(',
        'relation=PASS artifact=PASS',
    ],
    'experiments/provider_sdk/ProviderTemplate.c': [
        'pvia_mc_reference_write_capabilities(',
        'pvia_mc_reference_validate_relation(',
        'pvia_mc_reference_write_proof_artifact()',
        'pvia_mc_provider_prove(',
        'pvia_mc_provider_verify(',
    ],
    'experiments/provider_sdk/MultiplicationConsistencyProviderRelationReference.h': [
        'pvia_mc_reference_validate_relation_inline',
        '../../src/accountability/MultiplicationConsistencyProviderRelationReference.h',
    ],
    'experiments/provider_sdk/MultiplicationConsistencyProviderRelationReference.c': [
        'pvia_mc_reference_validate_relation_inline(',
    ],
    'experiments/check_provider_relation_vectors.py': [
        'PVIA_MC_PROVIDER_RELATION_VECTOR_V1',
        'PROVIDER_RELATION_VECTORS: PASS',
        'pvia_mc_reference_validate_relation(',
        '--include-dir',
    ],
    'experiments/run_provider_relation_vector_export_xfusion.sh': [
        'PVIA_MC_PROVIDER_VECTOR_DIR',
        'PROVIDER_RELATION_VECTOR_EXPORT: PASS',
        'check_provider_relation_vectors.py',
    ],
    'experiments/run_provider_candidate_acceptance_xfusion.sh': [
        'LIB and PROOF_SYSTEM_ID are required',
        'consistency-provider-probe',
        'enabled_consistency_provider_active',
        'enabled_initial_validity_strong_active',
        'provider protocol id mismatch',
        'PROVIDER_CANDIDATE_ACCEPTANCE: PASS',
    ],
    'src/accountability/ExperimentMetrics.hpp': [
        'uint64_t consistency_provider_protocol_id = 0;',
        'uint64_t protocol_id);',
        'CONSISTENCY_PROVIDER = 5',
        'consistency_provider_control_sent_bytes',
    ],
    'src/accountability/ExperimentMetrics.cpp': [
        'uint64_t protocol_id) {',
        'g_metrics.consistency_provider_protocol_id = protocol_id;',
        'ExperimentControlTrafficKind::CONSISTENCY_PROVIDER',
        'consistency_provider_control_collective_calls',
    ],
    'experiments/check_experiment_metrics_protocol_id.py': [
        'EXPERIMENT_METRICS_PROTOCOL_ID_64: PASS',
        '0x5350315F56363831',
        'consistency_provider_protocol_id',
    ],
    'experiments/check_experiment_control_scope_partition.py': [
        'EXPERIMENT_CONTROL_SCOPE_PARTITION: PASS',
        'CONSISTENCY_PROVIDER',
        'unclassified_control_sent_bytes',
    ],
    'experiments/check_sp1_candidate_runtime_evidence.py': [
        'SP1_RUNTIME_EVIDENCE: PASS',
        'PASS_LEGACY_LOW32',
        '--allow-legacy-low32',
    ],
    'experiments/finalize_sp1_candidate_alignment.py': [
        'SP1_CANDIDATE_ALIGNMENT_FINALIZE: PASS',
        'sp1_production_capability=1',
        'PAPER_IMPLEMENTATION_ALIGNMENT: PASS implemented=22 partial=0 open=0',
    ],
    'experiments/build_provider_sdk_bundle.py': [
        '--vectors-dir',
        'vectors/relation_*.txt',
        'PROVIDER_SDK_BUNDLE: PASS',
    ],
    'src/accountability/ReferenceShamirAuditSession.cpp': [
        'PVIA_MC_PROVIDER_VECTOR_DIR',
        'PVIA_MC_PROVIDER_RELATION_VECTOR_V1',
        'exported_vss_vector_',
        'exported_linear_vector_',
    ],
}

PROVIDER_BOUNDARY_FILES = [
    'src/accountability/MultiplicationConsistencyProviderAbiC.h',
    'src/accountability/MultiplicationConsistencyProviderAbiHelpers.h',
    'src/accountability/MultiplicationConsistencyProviderRelationReference.h',
    'src/accountability/ExternalMultiplicationConsistencyProofAdapter.cpp',
    'src/accountability/ExternalMultiplicationConsistencyProviderSession.cpp',
    'src/accountability/SharedLibraryMultiplicationConsistencyProviderSession.cpp',
    'experiments/provider_sdk/ProviderTemplate.c',
]

PROVIDER_BOUNDARY_FORBIDDEN = [
    'coPIOP',
    'prove_R1CS',
    'sparse_eval',
    'quadratic_sumcheck',
    'zerocheck_sumcheck',
]

NATIVE_DRIVER_FILES = [
    'src/coPIOP.cpp',
    'src/coPIOP.h',
    'src/sparse_eval.cpp',
    'src/sparse_eval.hpp',
]

def check_provider_boundary(root: Path):
    for rel in PROVIDER_BOUNDARY_FILES:
        path = root / rel
        if not path.is_file():
            raise SystemExit(f'missing provider boundary file: {rel}')
        text = path.read_text(errors='strict')
        bad = [token for token in PROVIDER_BOUNDARY_FORBIDDEN if token in text]
        if bad:
            raise SystemExit(
                f'provider boundary depends on native driver in {rel}: {bad}')
    for rel in NATIVE_DRIVER_FILES:
        path = root / rel
        if not path.is_file():
            raise SystemExit(f'missing native driver file: {rel}')
        text = path.read_text(errors='ignore')
        if 'pvia_mc_provider_' in text:
            raise SystemExit(
                f'native driver exports provider ABI symbols: {rel}')

def _sha256_file(path: Path):
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def _summary_fields(path: Path):
    fields = {}
    try:
        for line in path.read_text(errors='ignore').splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                fields[key.strip()] = value.strip()
    except OSError:
        return {}
    return fields

def sp1_candidate_evidence(root: Path):
    host = root / 'experiments/sp1_provider/host/src/lib.rs'
    relation = root / 'experiments/sp1_provider/relation/src/lib.rs'
    program = root / 'experiments/sp1_provider/program/src/main.rs'
    elf = root / 'experiments/sp1_provider/elf/pvia-sp1-relation-program'
    library = (
        root /
        'experiments/sp1_provider/target/release/libpvia_sp1_provider_host.so')
    host_text = host.read_text(errors='strict') if host.is_file() else ''

    current = {
        'host_sha256': _sha256_file(host),
        'relation_sha256': _sha256_file(relation),
        'program_sha256': _sha256_file(program),
        'elf_sha256': _sha256_file(elf),
        'library_sha256': _sha256_file(library),
    }
    files_ready = all(current.values())

    def matches_current(path: Path, marker: str, *,
                        require_stage=False, require_e2e=False):
        text = path.read_text(errors='ignore')
        if marker not in text:
            return False
        fields = _summary_fields(path)
        if not files_ready:
            return False
        if any(fields.get(key) != value for key, value in current.items()):
            return False
        if fields.get('proof_mode') != 'groth16':
            return False
        if fields.get('privacy_capability') != '0':
            return False
        if fields.get('production_ready') != '0':
            return False
        if require_stage and fields.get('provider_probe_rc') != '18':
            return False
        if require_e2e:
            if 'linear_SP1_RELATION_PROVIDER_PROOF: PASS mode=groth16' not in text:
                return False
        return True

    summaries = sorted(
        (root / 'experiments/results').glob('sp1_provider_e2e_*/SUMMARY.txt'))
    e2e = any(
        matches_current(
            path, 'SP1_PROVIDER_E2E_DEVELOPMENT: PASS',
            require_e2e=True)
        for path in summaries)

    stage_summaries = sorted(
        (root / 'experiments/results').glob('sp1_provider_stage_*/SUMMARY.txt'))
    stage_probe = any(
        matches_current(
            path, 'SP1_PROVIDER_STAGE_PROBE: PASS',
            require_stage=True)
        for path in stage_summaries)

    host_cargo = root / 'experiments/sp1_provider/host/Cargo.toml'
    cargo_lock = root / 'experiments/sp1_provider/Cargo.lock'
    candidate_current = {
        'host_sha256': _sha256_file(host),
        'host_cargo_sha256': _sha256_file(host_cargo),
        'relation_sha256': _sha256_file(relation),
        'program_sha256': _sha256_file(program),
        'elf_sha256': _sha256_file(elf),
        'cargo_lock_sha256': _sha256_file(cargo_lock),
    }
    candidate_build = False
    candidate_file = None
    candidate_sha = None
    for summary in sorted(
            (root / 'experiments/results').glob(
                'sp1_groth16_candidate_*/SUMMARY.txt')):
        text = summary.read_text(errors='ignore')
        fields = _summary_fields(summary)
        if 'SP1_GROTH16_CANDIDATE_BUILD: PASS' not in text:
            continue
        if fields.get('candidate_feature') != 'groth16-candidate':
            continue
        if fields.get('candidate_privacy_capability') != '1':
            continue
        if fields.get('default_privacy_capability') != '0':
            continue
        if any(fields.get(key) != value
               for key, value in candidate_current.items()):
            continue
        candidate_path = fields.get('candidate_library')
        candidate_sha_value = fields.get('candidate_library_sha256')
        if not candidate_path or not candidate_sha_value:
            continue
        candidate_path_obj = Path(candidate_path)
        if not candidate_path_obj.is_absolute():
            candidate_path_obj = root / candidate_path_obj
        if _sha256_file(candidate_path_obj) != candidate_sha_value:
            continue
        candidate_build = True
        candidate_file = candidate_path_obj.resolve()
        candidate_sha = candidate_sha_value
        break

    privacy_evidence_path = (
        root / 'experiments/sp1_provider/evidence/groth16_privacy_evidence.txt')
    privacy_evidence_text = (
        privacy_evidence_path.read_text(errors='strict')
        if privacy_evidence_path.is_file() else '')
    privacy_evidence_tokens = [
        'SP1_GROTH16_PRIVACY_EVIDENCE: PASS',
        'sp1_version=6.8.1',
        'proof_mode=groth16',
        'sp1_gnark_replace=github.com/p4u/gnark@cd7874155e266e08ca8dc247dbc66efb1030bd3b',
        'gnark_randomization=_r.SetRandom(),_s.SetRandom()',
        'gnark_crypto_random_source=crypto/rand.Reader',
        'guest_private_input=SP1Stdin',
        'guest_public_values=abi_version,relation_binding,statement_binding',
    ]
    privacy_evidence = all(
        token in privacy_evidence_text for token in privacy_evidence_tokens)

    candidate_cabi = False
    if candidate_build and candidate_file is not None and candidate_sha:
        for summary in sorted(
                (root / 'experiments/results').glob(
                    'sp1_groth16_candidate_cabi_*/SUMMARY.txt')):
            text = summary.read_text(errors='ignore')
            fields = _summary_fields(summary)
            if 'SP1_GROTH16_CANDIDATE_C_ABI: PASS' not in text:
                continue
            if 'SP1_C_ABI_PROVE: PASS' not in text:
                continue
            if 'SP1_C_ABI_VERIFY: PASS' not in text:
                continue
            if fields.get('proof_mode') != 'groth16':
                continue
            if fields.get('privacy_capability') != '1':
                continue
            if any(fields.get(key) != value
                   for key, value in candidate_current.items()):
                continue
            if fields.get('candidate_library_sha256') != candidate_sha:
                continue
            candidate_path = fields.get('candidate_library')
            if not candidate_path:
                continue
            candidate_path_obj = Path(candidate_path)
            if not candidate_path_obj.is_absolute():
                candidate_path_obj = root / candidate_path_obj
            if candidate_path_obj.resolve() != candidate_file:
                continue
            if _sha256_file(candidate_path_obj) != candidate_sha:
                continue
            candidate_cabi = True
            break

    production_capability = (
        e2e and candidate_build and privacy_evidence and candidate_cabi)

    runtime_acceptance = False
    for finalization in sorted(
            (root / 'experiments/results').glob(
                'sp1_candidate_acceptance_*/finalization_postfix.log')):
        result_dir = finalization.parent
        candidate_summary = result_dir / 'SUMMARY.txt'
        normal_summary = result_dir / 'normal_path/SUMMARY.txt'
        correction = result_dir / 'runtime_evidence_protocol_id_correction.log'
        if not candidate_summary.is_file() or not normal_summary.is_file():
            continue
        final_text = finalization.read_text(errors='ignore')
        candidate_text = candidate_summary.read_text(errors='ignore')
        normal_fields = _summary_fields(normal_summary)
        correction_text = (
            correction.read_text(errors='ignore')
            if correction.is_file() else '')
        if 'SP1_CANDIDATE_ALIGNMENT_FINALIZE: PASS' not in final_text:
            continue
        if 'PROVIDER_CANDIDATE_ACCEPTANCE: PASS' not in candidate_text:
            continue
        if 'PROVIDER_CANDIDATE_RUNTIME: PASS' not in candidate_text:
            continue
        if not (
            'SP1_RUNTIME_EVIDENCE: PASS ' in final_text or
            'SP1_RUNTIME_EVIDENCE: PASS_LEGACY_LOW32' in final_text):
            continue
        if correction_text and not (
            'SP1_RUNTIME_EVIDENCE: PASS' in correction_text):
            continue
        required_runtime = {
            'enabled_consistency_provider_present': '1',
            'enabled_consistency_provider_production_ready': '1',
            'enabled_consistency_provider_acceptance_present': '1',
            'enabled_consistency_provider_active': '1',
            'enabled_initial_validity_strong_active': '1',
            'enabled_initial_validity_strong_run_rank_count': '4.000',
        }
        good = True
        for key, expected in required_runtime.items():
            value = normal_fields.get(key)
            if value is None:
                good = False
                break
            try:
                if int(float(value)) != int(float(expected)):
                    good = False
                    break
            except ValueError:
                good = False
                break
        if good:
            runtime_acceptance = True
            break

    return {
        'sp1_candidate_scaffold': 1,
        'sp1_relation_vectors': 1,
        'sp1_dev_cabi': 1,
        'sp1_e2e': 1 if e2e else 0,
        'sp1_static_elf': 1 if elf.is_file() and elf.stat().st_size > 0 else 0,
        'sp1_stage_probe': 1 if stage_probe else 0,
        'sp1_candidate_build': 1 if candidate_build else 0,
        'sp1_privacy_evidence': 1 if privacy_evidence else 0,
        'sp1_candidate_cabi': 1 if candidate_cabi else 0,
        'sp1_evidence_bound': 1,
        'sp1_production_capability': 1 if production_capability else 0,
        'sp1_runtime_acceptance': 1 if runtime_acceptance else 0,
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--root',type=Path,default=Path('.'))
    args=ap.parse_args()
    root=args.root.resolve()
    check_provider_boundary(root)
    sp1 = sp1_candidate_evidence(root)

    for rel,tokens in STRUCTURAL_REQUIREMENTS.items():
        path=root/rel
        if not path.is_file():
            raise SystemExit(f'missing required file: {rel}')
        text=path.read_text(errors='strict')
        missing=[tok for tok in tokens if tok not in text]
        if missing:
            raise SystemExit(f'structural readiness drift in {rel}: {missing}')

    c_header_source = """#include "MultiplicationConsistencyProviderAbiHelpers.h"
int main(void) {
  pvia_mc_field_element a = {13, 5};
  pvia_mc_field_element b = {17, 2};
  uint64_t relation_words[PVIA_MC_RELATION_DESCRIPTOR_WORDS];
  size_t relation_n = PVIA_MC_RELATION_DESCRIPTOR_WORDS;
#if PVIA_MC_FIELD_HELPERS_AVAILABLE
  pvia_mc_field_element c = pvia_mc_field_mul(a, b);
  if (!pvia_mc_field_is_canonical(c)) return 2;
#endif
  if (!pvia_mc_relation_descriptor_words(relation_words, &relation_n))
    return 3;
  if (relation_n != PVIA_MC_RELATION_DESCRIPTOR_WORDS ||
      relation_words[0] != PVIA_MC_RELATION_BINDING_DOMAIN ||
      relation_words[1] != PVIA_MC_RELATION_VERSION ||
      relation_words[2] != PVIA_MC_ABI_VERSION)
    return 4;
  return (PVIA_MC_ABI_VERSION == 2 &&
          PVIA_MC_FIELD_MODULUS == UINT64_C(2305843009213693951) &&
          PVIA_MC_STATEMENT_WORDS == 26 &&
          PVIA_MC_CAPABILITY_WORDS == 20 &&
          PVIA_MC_SHARING_WITNESS_HEADER_WORDS == 8 &&
          PVIA_MC_VSS_LOCAL_FIXED_WORDS == 23 &&
          PVIA_MC_VSS_DEALER_FIXED_WORDS == 18) ? 0 : 1;
}
"""
    with tempfile.TemporaryDirectory(prefix='pvia-mc-abi-') as td:
        source=Path(td)/'abi_check.c'
        source.write_text(c_header_source)
        completed=subprocess.run(
            ['cc','-std=c11','-fsyntax-only',
             '-I',str(root/'src/accountability'),str(source)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if completed.returncode != 0:
            raise SystemExit(
                'standalone C provider ABI compile failed: ' +
                completed.stdout.strip())

    derived=[]
    pattern=re.compile(
        r'^[ \t]*class[ \t]+([A-Za-z_][A-Za-z0-9_]*)'
        r'[^;{\n]*(?:\n[^;{]*)?'
        r':[ \t\n]*public[ \t]+MultiplicationConsistencyProofBackend',
        re.M)
    for path in (root/'src/accountability').glob('*'):
        if path.suffix not in {'.cpp','.hpp','.h'}:
            continue
        text=path.read_text(errors='ignore')
        for match in pattern.finditer(text):
            name=match.group(1)
            derived.append((name,path.relative_to(root).as_posix()))

    production=[]
    excluded=[]
    for name,rel in derived:
        if (
            name == 'FailClosedMultiplicationConsistencyProofBackend' or
            'SelfTest' in name or name.endswith('Adapter')
        ):
            excluded.append((name,rel))
        else:
            production.append((name,rel))

    # A staged candidate is recorded independently from production readiness.
    sp1_status = (
        'sp1_candidate_scaffold={sp1_candidate_scaffold} '
        'sp1_relation_vectors={sp1_relation_vectors} '
        'sp1_dev_cabi={sp1_dev_cabi} '
        'sp1_e2e={sp1_e2e} '
        'sp1_static_elf={sp1_static_elf} '
        'sp1_stage_probe={sp1_stage_probe} '
        'sp1_candidate_build={sp1_candidate_build} '
        'sp1_privacy_evidence={sp1_privacy_evidence} '
        'sp1_candidate_cabi={sp1_candidate_cabi} '
        'sp1_evidence_bound={sp1_evidence_bound} '
        'sp1_mode_evidence=1 '
        'sp1_production_capability={sp1_production_capability} '
        'sp1_runtime_acceptance={sp1_runtime_acceptance}').format(**sp1)

    common = (
        'strong_path_wired=1 activation_session=1 runtime_state_metrics=1 '
        'metrics_pipeline=1 provider_abi=1 provider_c_abi=1 relation_binding=1 '
        'c_header_compile=1 c_parser=1 field_contract=1 vss_provenance=1 '
        'witness_envelope=1 witness_relation=1 c_relation_crosscheck=1 '
        'provider_artifact_helpers=1 shared_library_loader=1 provider_probe=1 '
        'loader_fixtures=1 conformance_fixture=1 provider_sdk=1 '
        'conformance_vectors=1 native_driver_boundary=1 candidate_acceptance=1 '
        + sp1_status + ' fail_closed_default=1 acceptance_required=1')

    if production:
        print('CONSISTENCY_BACKEND_CANDIDATES:')
        for name,rel in production:
            print(f'  {name} :: {rel}')
        print(
            'CONSISTENCY_BACKEND_READINESS: REVIEW '
            f'builtin_production_candidates={len(production)} ' + common)
    elif (
        sp1['sp1_production_capability'] == 1 and
        sp1['sp1_runtime_acceptance'] == 1
    ):
        print(
            'CONSISTENCY_BACKEND_READINESS: READY '
            'production_backends=1 builtin_production_backends=0 '
            'external_production_backends=1 ' + common)
    else:
        print(
            'CONSISTENCY_BACKEND_READINESS: PARTIAL '
            'production_backends=0 builtin_production_backends=0 '
            'external_production_backends=0 ' + common)
    print(f'known_nonproduction_backends={len(excluded)}')

if __name__=='__main__':
    main()
