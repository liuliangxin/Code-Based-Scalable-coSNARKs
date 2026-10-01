#include "ReferenceResidualMpcSelfTest.hpp"

#include "ReferenceShamirResidualMpcBackend.hpp"
#include "ResidualMpcMaliciousSecurity.hpp"
#include "AttestedResidualMpcBackend.hpp"
#include "AttestedResidualRuntimeBundle.hpp"
#include "ExternalMultiplicationConsistencyProviderSession.hpp"
#include "MultiplicationConsistencyProviderAbi.hpp"
#include "MultiplicationConsistencySharingWitness.hpp"
#include "ResidualActivationScope.hpp"
#include "AuthenticatedMpcAbortEvidence.hpp"
#include "PrivateResidualRegistry.hpp"
#include "AuthenticatedResidualProtocol.hpp"
#include "FoldResidualComputationBackend.hpp"
#include "KernelResidualEvaluator.hpp"
#include "SecureAuditComposition.hpp"
#include "ExperimentMetrics.hpp"

#include <mpi.h>

#include <cstring>
#include <iostream>
#include <vector>

namespace pvia {
namespace {

constexpr u64 SELFTEST_AUTH_SCHEME = 0x50565253454c4641ULL; // PVRSELFA
constexpr u64 SELFTEST_STATE_DOMAIN = 0x5056525354415445ULL; // PVRSTATE
constexpr u64 SELFTEST_EXPECTED_DOMAIN = 0x5056524558504543ULL; // PVREXPEC
constexpr u64 SELFTEST_ACTUAL_DOMAIN = 0x5056524143545541ULL; // PVRACTUA
constexpr u64 SELFTEST_AUX_DOMAIN = 0x5056524155583031ULL; // PVRAUX01
constexpr u64 SELFTEST_PROOF_DOMAIN = 0x5056525052463031ULL; // PVRPRF01
constexpr u64 SELFTEST_TRANSCRIPT_DOMAIN = 0x50565254524e3031ULL; // PVRTRN01
constexpr u64 SELFTEST_SCOPE_DOMAIN = 0x50565253434f5045ULL; // PVRSCOPE

void append_digest_words_selftest(
    const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

class SelfTestResidualAuthenticator final
    : public PrivateResidualShareAuthenticator {
public:
    uint64_t SchemeId() const override { return SELFTEST_AUTH_SCHEME; }

    bool Authenticate(
        const PrivateResidualShare& share,
        PrivateResidualAuthenticationArtifact* artifact) const override {
        if (!artifact || !share.computation_valid ||
            share.computation_binding == Digest{} ||
            share.source_state_id == 0 ||
            share.source_state_authentication_scheme_id != SchemeId() ||
            share.source_state_authentication_binding == Digest{})
            return false;
        artifact->available = true;
        artifact->cryptographically_authenticated = true;
        artifact->scheme_id = SchemeId();
        artifact->computation_binding = share.computation_binding;
        artifact->source_state_id = share.source_state_id;
        artifact->source_state_owner = share.source_state_owner;
        artifact->source_state_digest = share.source_state_digest;
        artifact->source_state_authentication_scheme_id =
            share.source_state_authentication_scheme_id;
        artifact->source_state_authentication_binding =
            share.source_state_authentication_binding;
        artifact->public_aux_root = share.public_aux_root;
        artifact->operation_statement_binding =
            share.operation_statement_binding;
        artifact->proof_commitment = hash_words({
            SELFTEST_PROOF_DOMAIN, share.label.sid,
            share.ref.owner, share.ref.object_id});
        artifact->transcript_binding = hash_words({
            SELFTEST_TRANSCRIPT_DOMAIN, share.label.sid,
            share.checkpoint, share.ref.owner, share.ref.object_id});
        artifact->binding =
            compute_private_residual_authentication_artifact_binding(*artifact);
        return validate_private_residual_authentication_artifact(
            share, *artifact);
    }
};

// Synthetic multiplication-consistency backend for MPI wiring tests only.
// It checks the dealer-local witness before emitting a marker proof, but its
// public Verify routine is not a cryptographic ZK verifier. It is intentionally
// confined to this anonymous self-test namespace and never installed by the
// production/reference runtime adapter.
class SelfTestMultiplicationConsistencyBackend final
    : public MultiplicationConsistencyProofBackend {
public:
    size_t prove_count() const { return prove_count_; }

    MultiplicationConsistencyCapabilities Capabilities() const override {
        MultiplicationConsistencyCapabilities capabilities;
        capabilities.available = true;
        capabilities.malicious_sound = true;
        capabilities.zero_knowledge = true;
        capabilities.binds_input_sharings = true;
        capabilities.binds_output_sharing = true;
        capabilities.protocol_id = 0x4d554c5445535450ULL; // MULTESTP
        capabilities.relation_binding =
            compute_multiplication_consistency_relation_binding();
        capabilities.implementation_binding =
            hash_words({0x4d554c5445535449ULL}); // MULTESTI
        capabilities.capability_binding =
            compute_multiplication_consistency_capability_binding(capabilities);
        return capabilities;
    }

    MultiplicationConsistencyProofArtifact Prove(
        const MultiplicationConsistencyStatement& statement,
        const MultiplicationConsistencyWitness& witness) const override {
        MultiplicationConsistencyProofArtifact proof;
        if (!validate_multiplication_consistency_statement(statement) ||
            witness.product_value != witness.lhs_share * witness.rhs_share)
            return proof;
        auto validate_input = [&](
            const std::vector<u64>& words, const Digest& binding,
            const F& expected_share) -> bool {
            MultiplicationConsistencySharingWitnessEnvelope envelope;
            if (!decode_multiplication_consistency_sharing_witness(
                    words, &envelope) ||
                envelope.sharing_binding != binding)
                return false;
            if (envelope.kind ==
                MultiplicationConsistencySharingWitnessKind::
                    LINEAR_COMBINATION) {
                ReferenceLinearSharingProvenance linear;
                if (!decode_reference_linear_sharing_provenance(
                        envelope.payload_words, &linear) ||
                    linear.binding != binding ||
                    linear.local_share != expected_share)
                    return false;
                for (const auto& source : linear.sources) {
                    if (source.local_witness.participant !=
                            static_cast<int>(statement.dealer) ||
                        source.local_witness.transcript_binding !=
                            source.sharing_binding)
                        return false;
                }
                return true;
            }
            if (envelope.kind !=
                MultiplicationConsistencySharingWitnessKind::VSS_LOCAL)
                return false;
            ReferenceVssLocalWitness direct;
            if (!decode_reference_vss_local_witness(
                    envelope.payload_words, &direct) ||
                direct.participant != static_cast<int>(statement.dealer) ||
                direct.transcript_binding != binding ||
                direct.local_row_words.size() < 2)
                return false;
            const F direct_value(
                static_cast<long long>(direct.local_row_words[0]),
                static_cast<long long>(direct.local_row_words[1]));
            return direct_value == expected_share;
        };
        MultiplicationConsistencySharingWitnessEnvelope output_envelope;
        ReferenceVssDealerWitness output_witness;
        if (!validate_input(
                witness.lhs_sharing_witness_words,
                statement.lhs_sharing_binding, witness.lhs_share) ||
            !validate_input(
                witness.rhs_sharing_witness_words,
                statement.rhs_sharing_binding, witness.rhs_share) ||
            !decode_multiplication_consistency_sharing_witness(
                witness.output_sharing_witness_words, &output_envelope) ||
            output_envelope.kind !=
                MultiplicationConsistencySharingWitnessKind::VSS_DEALER ||
            output_envelope.sharing_binding !=
                statement.output_sharing_binding ||
            !decode_reference_vss_dealer_witness(
                output_envelope.payload_words, &output_witness) ||
            output_witness.dealer != static_cast<int>(statement.dealer) ||
            output_witness.transcript_binding !=
                statement.output_sharing_binding ||
            output_witness.coefficient_words.size() < 2)
            return proof;
        const F shared_constant(
            static_cast<long long>(output_witness.coefficient_words[0]),
            static_cast<long long>(output_witness.coefficient_words[1]));
        if (shared_constant != witness.product_value) return proof;
        proof.available = true;
        proof.cryptographically_authenticated = true;
        proof.zero_knowledge = true;
        proof.proof_system_id = 0x4d554c54U; // MULT
        proof.statement_binding = statement.statement_binding;
        proof.transcript_binding = Transcript(statement);
        proof.proof_words = {
            0x4d554c5445535457ULL,
            static_cast<u64>(statement.dealer)};
        proof.proof_commitment =
            compute_multiplication_consistency_proof_commitment(proof);
        ++prove_count_;
        return proof;
    }

    bool Verify(
        const MultiplicationConsistencyStatement& statement,
        const MultiplicationConsistencyProofArtifact& proof) const override {
        if (!validate_multiplication_consistency_proof_artifact(
                statement, proof))
            return false;
        return proof.proof_words == std::vector<u64>{
                   0x4d554c5445535457ULL,
                   static_cast<u64>(statement.dealer)} &&
               proof.transcript_binding == Transcript(statement);
    }

private:
    mutable size_t prove_count_ = 0;

    static Digest Transcript(
        const MultiplicationConsistencyStatement& statement) {
        std::vector<u64> words = {
            0x4d554c5445535454ULL,
            statement.sid, statement.checkpoint,
            statement.multiplication_id, statement.dealer};
        append_digest_words_selftest(statement.statement_binding, &words);
        append_digest_words_selftest(statement.output_sharing_binding, &words);
        return hash_words(words);
    }
};

// Synthetic malicious-security provider for adapter wiring tests only.
// It is confined to this self-test translation unit and is not a production
// public-abort or malicious-security implementation.
class SelfTestResidualMpcMaliciousSecurityProvider final
    : public ResidualMpcMaliciousSecurityProvider {
public:
    SelfTestResidualMpcMaliciousSecurityProvider(
        const Digest& residual_implementation_binding,
        const Digest& strong_consistency_capability_binding,
        const Digest& authenticated_transport_capability_binding)
        : residual_implementation_binding_(residual_implementation_binding),
          strong_consistency_capability_binding_(
              strong_consistency_capability_binding),
          identifiable_abort_capability_binding_(
              make_signed_equivocation_abort_evidence_capabilities(
                  authenticated_transport_capability_binding).capability_binding) {}

    ResidualMpcMaliciousSecurityCapabilities Capabilities() const override {
        ResidualMpcMaliciousSecurityCapabilities c;
        c.available = true;
        c.protocol_id = 0x52534d4154545354ULL; // RSMATTST
        c.security_level = RobustAuditSecurityLevel::MALICIOUS_ABORT;
        c.malicious_secure = true;
        c.binds_residual_implementation = true;
        c.binds_failure_before_activation = true;
        c.publicly_identifiable_abort = true;
        c.guaranteed_output_delivery = false;
        c.residual_implementation_binding = residual_implementation_binding_;
        c.strong_consistency_capability_binding =
            strong_consistency_capability_binding_;
        c.identifiable_abort_capability_binding =
            identifiable_abort_capability_binding_;
        c.delivery_capability_binding = Digest{};
        c.implementation_binding = hash_words({0x52534d415454494dULL});
        c.capability_binding =
            compute_residual_mpc_malicious_security_capability_binding(c);
        return c;
    }

    ResidualMpcSecurityAttestation AttestActivatedState(
        const ObligationSet& scope,
        const ResidualMpcCapabilities& residual,
        const Digest& activation_binding,
        const Digest& strong_consistency_capability_binding) const override {
        ResidualMpcSecurityAttestation a;
        const auto security = Capabilities();
        if (!validate_residual_mpc_capabilities(residual) ||
            residual.implementation_binding != residual_implementation_binding_ ||
            activation_binding == Digest{} ||
            strong_consistency_capability_binding !=
                security.strong_consistency_capability_binding)
            return a;
        a.available = true;
        a.sid = scope.session_id;
        a.checkpoint = scope.checkpoint;
        a.security_level = security.security_level;
        a.scope_binding = compute_collective_scope_binding(scope);
        a.residual_mpc_capability_binding = residual.capability_binding;
        a.activation_binding = activation_binding;
        a.strong_consistency_capability_binding =
            strong_consistency_capability_binding;
        a.identifiable_abort_capability_binding =
            security.identifiable_abort_capability_binding;
        a.delivery_capability_binding = security.delivery_capability_binding;
        a.security_capability_binding = security.capability_binding;
        a.attestation_binding = compute_residual_mpc_security_attestation_binding(a);
        return a;
    }

    bool VerifyAttestation(
        const ObligationSet& scope,
        const ResidualMpcCapabilities& residual,
        const ResidualMpcSecurityAttestation& attestation,
        RobustAuditSecurityLevel required_security) const override {
        return validate_residual_mpc_security_attestation(
            scope, residual, Capabilities(), attestation, required_security);
    }

private:
    Digest residual_implementation_binding_{};
    Digest strong_consistency_capability_binding_{};
    Digest identifiable_abort_capability_binding_{};
};

struct ProviderCaseResult {
    bool ran = false;
    bool batch_ok = false;
    bool localized = false;
    bool production_gate_rejected = false;
};

ProviderCaseResult run_provider_integration_case(
    int rank, int world_size, bool inject_fault) {
    ProviderCaseResult result;
    if (world_size != 4 || rank < 0 || rank >= world_size)
        return result;

    const uint64_t sid =
        0x525350524f560000ULL + (inject_fault ? 2ULL : 1ULL);
    const CheckpointId checkpoint = static_cast<CheckpointId>(
        0x7100 + (inject_fault ? 2 : 1));
    const uint32_t round = inject_fault ? 22U : 21U;
    const uint32_t faulty_owner = static_cast<uint32_t>(world_size / 2);
    const OperationRef local_ref{
        static_cast<uint32_t>(rank),
        static_cast<uint64_t>(4000 + rank)};

    std::vector<F> input;
    for (int i = 0; i < 8; ++i)
        input.push_back(F(static_cast<long long>(1 + rank * 8 + i)));
    const F challenge(5);
    std::vector<F> expected;
    if (!recompute_fold_rs_output(input, challenge, &expected) ||
        expected.empty())
        return result;
    std::vector<F> actual = expected;
    if (inject_fault && static_cast<uint32_t>(rank) == faulty_owner)
        actual.front() += F(1);

    AuditStateView state;
    state.id = static_cast<StateId>(0x5000 + rank);
    state.label.sid = sid;
    state.label.phase = Phase::FOLD;
    state.label.round = round;
    state.label.owner = static_cast<uint32_t>(rank);
    state.label.obligation = Obligation::DERIVE;
    state.label.object_id = state.id;
    state.digest = hash_field_vector(input);
    state.name = "reference-residual-provider-state";
    state.debug_only = true;
    const Digest state_authentication = hash_words({
        SELFTEST_AUTH_SCHEME, sid, state.id,
        static_cast<u64>(rank)});

    AuditOperationView operation;
    operation.ref = local_ref;
    operation.label.sid = sid;
    operation.label.phase = Phase::FOLD;
    operation.label.round = round;
    operation.label.owner = static_cast<uint32_t>(rank);
    operation.label.obligation = Obligation::FOLD;
    operation.label.object_id = local_ref.object_id;
    operation.relation = RelationKind::FOLDING;
    operation.kernel = AuditRelationKernel::FOLD_RS;
    operation.expected = hash_field_vector(expected);
    operation.actual = hash_field_vector(actual);
    operation.predecessor_root = hash_words(std::vector<u64>{});
    operation.predecessor_count = 0;
    operation.checkpoint = checkpoint;
    operation.active = true;

    StateDependencyEvidence state_evidence;
    state_evidence.owner = static_cast<uint32_t>(rank);
    state_evidence.state_id = state.id;
    state_evidence.digest = state.digest;
    operation.state_dependency_root =
        compute_state_dependency_root({state_evidence});
    operation.state_dependency_count = 1;

    PublicAuxEvidence aux_evidence;
    aux_evidence.kind = AuditPublicAuxKind::FOLD_CHALLENGE;
    aux_evidence.digest = hash_field_vector({challenge});
    operation.public_aux_root = compute_public_aux_root({aux_evidence});
    operation.public_aux_count = 1;
    operation.relation_statement = compute_relation_statement(
        operation.label, operation.relation, operation.kernel,
        operation.expected, operation.predecessor_root,
        operation.predecessor_count, operation.state_dependency_root,
        operation.state_dependency_count, operation.public_aux_root,
        operation.public_aux_count);
    if (operation.relation_statement == Digest{}) return result;

    PrivateResidualShareStore shares;
    SelfTestResidualAuthenticator authenticator;
    FoldResidualComputationBackend fold_backend(shares, &authenticator);
    BackendKernelResidualEvaluator fold_evaluator(
        fold_backend, {AuditRelationKernel::FOLD_RS});

    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready()) return result;
    ReferenceShamirMpc mpc(rank, world_size, (world_size - 1) / 3);
    ReferenceShamirResidualMpcBackend residual_backend(
        shares, mpc, exchange);
    MpcBackedAuthenticatedResidualProtocol passive(
        residual_backend, RobustAuditSecurityLevel::REFERENCE_PASSIVE);
    if (!passive.ready()) return result;
    ProtocolBackedCollectiveResidualEngine collective_engine(passive);

    SecureAuditComponents components;
    components.collective_engine = &collective_engine;
    components.kernel_evaluators.push_back(&fold_evaluator);
    ComposedSecureAuditProvider provider(
        components, true, RobustAuditSecurityLevel::REFERENCE_PASSIVE);
    SecureAuditRequirements reference_requirements;
    reference_requirements.private_lane = true;
    reference_requirements.transfer_lane = false;
    reference_requirements.private_security_level =
        RobustAuditSecurityLevel::REFERENCE_PASSIVE;
    reference_requirements.required_kernels = {
        AuditRelationKernel::FOLD_RS};
    result.production_gate_rejected =
        !provider.Ready(reference_requirements);
    if (!result.production_gate_rejected) return result;

    provider.RegisterStateMetadata(state);
    provider.BindPrivateState(state, input);
    if (!provider.BindPrivateStateAuthentication(
            state, SELFTEST_AUTH_SCHEME, state_authentication))
        return result;
    provider.RegisterOperation(operation);
    provider.BindOperationStateDependencies(operation, {state.id});
    provider.BindPublicFieldAux(
        operation, AuditPublicAuxKind::FOLD_CHALLENGE, {challenge});
    provider.BindPrivateFieldOperation(
        operation, AuditPrivatePayloadKind::FIELD_VECTOR,
        AuditPayloadStage::REGISTER_INPUT, expected);
    provider.BindPrivateFieldOperation(
        operation, AuditPrivatePayloadKind::FIELD_VECTOR,
        AuditPayloadStage::ACTIVATE_OUTPUT, actual);
    provider.ActivateOperation(operation);
    provider.FinalizePrivateRelation(operation);

    ObligationSet scope;
    scope.session_id = sid;
    scope.phase = Phase::FOLD;
    scope.round = round;
    scope.generation = 1;
    scope.exact_round = true;
    scope.checkpoint = checkpoint;
    scope.checkpoint_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, checkpoint, round, 0x50524f56ULL});
    scope.obligations = {Obligation::FOLD};
    for (int owner = 0; owner < world_size; ++owner) {
        OperationRef ref{
            static_cast<uint32_t>(owner),
            static_cast<uint64_t>(4000 + owner)};
        scope.operations.push_back(ref);
        scope.private_operations.push_back(ref);
    }

    const ObligationSet synchronized =
        provider.SynchronizeFailureScope(scope, rank, world_size);
    if (synchronized.checkpoint != checkpoint ||
        synchronized.operations.size() != scope.operations.size() ||
        synchronized.private_operations.size() != scope.private_operations.size())
        return result;
    const BatchCheckResult batch =
        provider.PrivateBatchCheck(synchronized);
    if (!batch.available || !batch.cryptographically_authenticated)
        return result;
    result.ran = true;
    result.batch_ok = batch.ok;
    if (!inject_fault) {
        result.localized = true;
        return result;
    }
    if (batch.ok) return result;

    const Violation violation =
        provider.PrivateDispute(synchronized, batch);
    result.localized =
        violation.valid &&
        violation.responsible_rank == faulty_owner &&
        violation.checkpoint == checkpoint &&
        violation.relation == RelationKind::FOLDING &&
        violation.kernel == AuditRelationKernel::FOLD_RS &&
        violation.expected != violation.actual &&
        violation.residual_commitment != Digest{} &&
        violation.dispute_binding != Digest{};
    return result;
}

bool make_authenticated_share_bound(
    uint64_t sid, CheckpointId checkpoint, uint32_t round,
    const OperationRef& ref, bool faulty,
    const Digest& predecessor_root, uint32_t predecessor_count,
    PrivateResidualShare* share_out,
    PrivateResidualHandle* handle_out) {
    if (!share_out || !handle_out) return false;

    PrivateResidualShare share;
    share.ref = ref;
    share.label.sid = sid;
    share.label.phase = Phase::FOLD;
    share.label.round = round;
    share.label.owner = ref.owner;
    share.label.obligation = Obligation::FOLD;
    share.label.object_id = ref.object_id;
    share.relation = RelationKind::FOLDING;
    share.kernel = AuditRelationKernel::FOLD_RS;
    share.checkpoint = checkpoint;
    share.values = {F(0), faulty ? F(7) : F(0)};
    share.source_state_id = 1000 + ref.object_id;
    share.source_state_owner = ref.owner;
    share.source_state_digest = hash_words({
        SELFTEST_STATE_DOMAIN, sid, ref.owner, ref.object_id});
    share.source_state_authentication_scheme_id = SELFTEST_AUTH_SCHEME;
    share.source_state_authentication_binding = hash_words({
        SELFTEST_AUTH_SCHEME, sid, ref.owner, ref.object_id});
    share.public_aux_root = hash_words({
        SELFTEST_AUX_DOMAIN, sid, ref.owner, ref.object_id});
    share.expected = hash_words({
        SELFTEST_EXPECTED_DOMAIN, sid, ref.owner, ref.object_id});
    share.actual = faulty
        ? hash_words({SELFTEST_ACTUAL_DOMAIN, sid, ref.owner, ref.object_id})
        : share.expected;
    const Digest state_dependency_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, ref.owner, ref.object_id, 1});
    share.operation_statement_binding = compute_relation_statement(
        share.label, share.relation, share.kernel, share.expected,
        predecessor_root, predecessor_count, state_dependency_root, 1,
        share.public_aux_root, 1);
    share.computation_valid = true;
    share.computation_binding =
        compute_private_residual_computation_binding(share);

    PrivateResidualAuthenticationArtifact artifact;
    artifact.available = true;
    artifact.cryptographically_authenticated = true;
    artifact.scheme_id = SELFTEST_AUTH_SCHEME;
    artifact.computation_binding = share.computation_binding;
    artifact.source_state_id = share.source_state_id;
    artifact.source_state_owner = share.source_state_owner;
    artifact.source_state_digest = share.source_state_digest;
    artifact.source_state_authentication_scheme_id =
        share.source_state_authentication_scheme_id;
    artifact.source_state_authentication_binding =
        share.source_state_authentication_binding;
    artifact.public_aux_root = share.public_aux_root;
    artifact.operation_statement_binding =
        share.operation_statement_binding;
    artifact.proof_commitment = hash_words({
        SELFTEST_PROOF_DOMAIN, sid, ref.owner, ref.object_id});
    artifact.transcript_binding = hash_words({
        SELFTEST_TRANSCRIPT_DOMAIN, sid, ref.owner, ref.object_id});
    artifact.binding =
        compute_private_residual_authentication_artifact_binding(artifact);

    share.authentication = artifact;
    share.authentication_binding = artifact.binding;
    share.authenticated = true;
    share.commitment = compute_private_residual_share_commitment(share);
    if (!validate_private_residual_share(share))
        return false;

    PrivateResidualHandle handle;
    handle.ref = share.ref;
    handle.label = share.label;
    handle.relation = share.relation;
    handle.kernel = share.kernel;
    handle.checkpoint = share.checkpoint;
    handle.commitment = share.commitment;
    handle.available = true;
    handle.authenticated = true;

    *share_out = share;
    *handle_out = handle;
    return true;
}

bool make_authenticated_share(
    uint64_t sid, CheckpointId checkpoint, uint32_t round,
    const OperationRef& ref, bool faulty,
    PrivateResidualShare* share_out,
    PrivateResidualHandle* handle_out) {
    const Digest predecessor_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, ref.owner, ref.object_id, 0});
    return make_authenticated_share_bound(
        sid, checkpoint, round, ref, faulty,
        predecessor_root, 0, share_out, handle_out);
}

struct CaseResult {
    bool ran = false;
    bool batch_ok = false;
    bool localized = false;
    bool activated_before_failure = false;
    bool store_independent = false;
    bool activated_vss_bound = false;
    bool strong_zero_consistency = false;
    bool reference_security_attestation_empty = false;
    bool attested_malicious_gate = false;
    bool attested_scope_gate = false;
    bool runtime_bundle_bound = false;
    bool runtime_default_failclosed = false;
    bool sealed_activation_scope_bound = false;
    bool sealed_activation_local_fragment_bound = false;
    bool sealed_activation_sync_bound = false;
    bool sealed_activation_tamper_rejected = false;
    bool composed_security_provider_bound = false;
    bool detached_transport_scope_rejected = false;
    bool attested_batch_ok = false;
    bool attested_security_transcript_bound = false;
    bool attested_localized = false;
    bool failclosed_security_provider_rejected = false;
    bool attested_god_rejected = false;
    bool attested_state_drift_rejected = false;
    bool security_capability_gate_bound = false;
    bool passive_gate = false;
    bool malicious_abort_rejected = false;
    bool god_rejected = false;
};

CaseResult run_case(
    int rank, int world_size, bool inject_fault) {
    CaseResult result;
    if (world_size < 4 || rank < 0 || rank >= world_size)
        return result;

    const uint64_t sid =
        0x52534d5043540000ULL + (inject_fault ? 2ULL : 1ULL);
    const CheckpointId checkpoint =
        static_cast<CheckpointId>(0x7000 + (inject_fault ? 2 : 1));
    const uint32_t round = inject_fault ? 12U : 11U;
    const uint32_t faulty_owner =
        static_cast<uint32_t>(world_size / 2);

    ObligationSet scope;
    scope.session_id = sid;
    scope.phase = Phase::FOLD;
    scope.round = round;
    scope.generation = 1;
    scope.exact_round = true;
    scope.checkpoint = checkpoint;
    scope.checkpoint_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, checkpoint, round});
    scope.obligations = {Obligation::FOLD};
    for (int owner = 0; owner < world_size; ++owner) {
        OperationRef ref{
            static_cast<uint32_t>(owner),
            static_cast<uint64_t>(2000 + owner)};
        scope.operations.push_back(ref);
        scope.private_operations.push_back(ref);
    }

    PrivateResidualShareStore store;
    PrivateResidualRegistry registry;
    const OperationRef local_ref{
        static_cast<uint32_t>(rank),
        static_cast<uint64_t>(2000 + rank)};
    PrivateResidualShare local_share;
    PrivateResidualHandle local_handle;
    const bool local_fault =
        inject_fault && static_cast<uint32_t>(rank) == faulty_owner;
    if (!make_authenticated_share(
            sid, checkpoint, round, local_ref, local_fault,
            &local_share, &local_handle) ||
        !store.Put(local_share))
        return result;
    registry.Put(local_handle);
    const LocalResidualBatchView local_view =
        registry.BuildLocalBatchView(scope, static_cast<uint32_t>(rank));
    if (!local_view.complete_for_owner || !local_view.all_authenticated ||
        local_view.handles.size() != 1)
        return result;

    AuditCheckpointView sealed_checkpoint;
    sealed_checkpoint.id = scope.checkpoint;
    sealed_checkpoint.phase = scope.phase;
    sealed_checkpoint.round = scope.round;
    sealed_checkpoint.generation = scope.generation;
    sealed_checkpoint.operations = scope.operations;
    sealed_checkpoint.root = scope.checkpoint_root;
    sealed_checkpoint.sealed = true;

    auto populate_activation_materials = [&](
        PrivateAuditMaterialStore* materials, bool tamper_round,
        int owner_filter) {
        if (!materials) return;
        for (size_t i = 0; i < scope.operations.size(); ++i) {
            const OperationRef& ref = scope.operations[i];
            if (owner_filter >= 0 &&
                ref.owner != static_cast<uint32_t>(owner_filter))
                continue;
            AuditOperationView operation;
            operation.ref = ref;
            operation.label.sid = sid;
            operation.label.phase = scope.phase;
            operation.label.round =
                tamper_round && i == 0 ? round + 1 : round;
            operation.label.owner = ref.owner;
            operation.label.obligation = Obligation::FOLD;
            operation.label.object_id = ref.object_id;
            operation.relation = RelationKind::FOLDING;
            operation.kernel = AuditRelationKernel::FOLD_RS;
            operation.checkpoint = checkpoint;
            materials->RegisterOperation(operation);
            materials->MarkFinalized(ref);
        }
    };

    PrivateAuditMaterialStore activation_materials;
    populate_activation_materials(&activation_materials, false, -1);
    ObligationSet activation_scope;
    result.sealed_activation_scope_bound =
        build_private_residual_activation_scope(
            sealed_checkpoint, activation_materials, &activation_scope) &&
        activation_scope.session_id == scope.session_id &&
        activation_scope.phase == scope.phase &&
        activation_scope.round == scope.round &&
        activation_scope.generation == scope.generation &&
        activation_scope.exact_round == scope.exact_round &&
        activation_scope.checkpoint == scope.checkpoint &&
        activation_scope.checkpoint_root == scope.checkpoint_root &&
        activation_scope.obligations == scope.obligations &&
        activation_scope.operations == scope.operations &&
        activation_scope.private_operations == scope.private_operations &&
        activation_scope.transfer_operations.empty();
    if (!result.sealed_activation_scope_bound) return result;

    PrivateAuditMaterialStore tampered_activation_materials;
    populate_activation_materials(&tampered_activation_materials, true, -1);
    ObligationSet tampered_activation_scope;
    result.sealed_activation_tamper_rejected =
        !build_private_residual_activation_scope(
            sealed_checkpoint, tampered_activation_materials,
            &tampered_activation_scope);
    if (!result.sealed_activation_tamper_rejected) return result;

    PrivateAuditMaterialStore local_activation_materials;
    populate_activation_materials(
        &local_activation_materials, false, rank);
    ObligationSet local_activation_fragment;
    result.sealed_activation_local_fragment_bound =
        build_local_private_residual_activation_scope(
            sealed_checkpoint, local_activation_materials,
            static_cast<uint32_t>(rank), sid,
            &local_activation_fragment) &&
        local_activation_fragment.session_id == sid &&
        local_activation_fragment.checkpoint == checkpoint &&
        local_activation_fragment.operations.size() == 1 &&
        local_activation_fragment.operations.front() == local_ref &&
        local_activation_fragment.private_operations ==
            local_activation_fragment.operations &&
        local_activation_fragment.transfer_operations.empty() &&
        local_activation_fragment.obligations == scope.obligations;
    if (!result.sealed_activation_local_fragment_bound) return result;

    const int threshold = (world_size - 1) / 3;
    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready())
        return result;
    // Check the empty-provider case before an accepted provider is scoped
    // into the process registry.
    AttestedResidualRuntimeBundle default_failclosed_runtime(
        store, exchange, rank, world_size, threshold, sid, nullptr,
        MPI_COMM_WORLD);
    result.runtime_default_failclosed =
        !default_failclosed_runtime.ready() &&
        !default_failclosed_runtime.ActivateForScope(
            activation_scope, registry);

    SelfTestMultiplicationConsistencyBackend multiplication_backend;

    // Canonical provider ABI roundtrip.
    MultiplicationConsistencyStatement abi_statement;
    abi_statement.sid = sid;
    abi_statement.checkpoint = checkpoint;
    abi_statement.multiplication_id = 0x41424901ULL;
    abi_statement.dealer = static_cast<uint32_t>(rank);
    abi_statement.lhs_sharing_binding =
        hash_words({0x41424911ULL, static_cast<u64>(rank)});
    abi_statement.rhs_sharing_binding =
        hash_words({0x41424912ULL, static_cast<u64>(rank)});
    abi_statement.output_sharing_binding =
        hash_words({0x41424913ULL, static_cast<u64>(rank)});
    abi_statement.context_binding =
        hash_words({0x41424914ULL, sid, checkpoint});
    abi_statement.statement_binding =
        compute_multiplication_consistency_statement_binding(abi_statement);
    MultiplicationConsistencyStatement decoded_statement;
    const auto statement_words =
        encode_multiplication_consistency_statement_abi(abi_statement);
    if (!decode_multiplication_consistency_statement_abi(
            statement_words, &decoded_statement) ||
        decoded_statement.statement_binding !=
            abi_statement.statement_binding ||
        decoded_statement.dealer != abi_statement.dealer)
        return result;

    MultiplicationConsistencyWitness abi_witness;
    abi_witness.lhs_share = F(3, 4);
    abi_witness.rhs_share = F(5, 6);
    abi_witness.product_value =
        abi_witness.lhs_share * abi_witness.rhs_share;
    abi_witness.lhs_sharing_witness_words = {1, 2, 3};
    abi_witness.rhs_sharing_witness_words = {4, 5};
    abi_witness.output_sharing_witness_words = {6, 7, 8, 9};
    MultiplicationConsistencyWitness decoded_witness;
    const auto witness_words =
        encode_multiplication_consistency_witness_abi(abi_witness);
    if (!decode_multiplication_consistency_witness_abi(
            witness_words, &decoded_witness) ||
        decoded_witness.lhs_share != abi_witness.lhs_share ||
        decoded_witness.rhs_share != abi_witness.rhs_share ||
        decoded_witness.product_value != abi_witness.product_value ||
        decoded_witness.lhs_sharing_witness_words !=
            abi_witness.lhs_sharing_witness_words ||
        decoded_witness.rhs_sharing_witness_words !=
            abi_witness.rhs_sharing_witness_words ||
        decoded_witness.output_sharing_witness_words !=
            abi_witness.output_sharing_witness_words)
        return result;

    MultiplicationConsistencyCapabilities decoded_capabilities;
    const auto capabilities_words =
        encode_multiplication_consistency_capabilities_abi(
            multiplication_backend.Capabilities());
    if (!decode_multiplication_consistency_capabilities_abi(
            capabilities_words, &decoded_capabilities) ||
        decoded_capabilities.capability_binding !=
            multiplication_backend.Capabilities().capability_binding)
        return result;

    MultiplicationConsistencyProviderCallbacks provider_callbacks;
    provider_callbacks.prove =
        [&](const MultiplicationConsistencyStatement& statement,
            const MultiplicationConsistencyWitness& witness) {
            return multiplication_backend.Prove(statement, witness);
        };
    provider_callbacks.verify =
        [&](const MultiplicationConsistencyStatement& statement,
            const MultiplicationConsistencyProofArtifact& proof) {
            return multiplication_backend.Verify(statement, proof);
        };
    ExternalMultiplicationConsistencyProviderSession provider_session(
        multiplication_backend.Capabilities(),
        0x4d554c54U,
        std::move(provider_callbacks));
    if (!provider_session.Activate(
            rank, world_size, MPI_COMM_WORLD) ||
        !provider_session.active() ||
        !provider_session.acceptance().available)
        return result;

    AttestedResidualRuntimeBundle residual_runtime(
        store, exchange, rank, world_size, threshold, sid,
        nullptr, MPI_COMM_WORLD);
    if (!result.runtime_default_failclosed ||
        !residual_runtime.ready() ||
        !residual_runtime.ActivateSealedCheckpoint(
            sealed_checkpoint, local_activation_materials, registry))
        return result;
    const ObligationSet& synchronized_activation_scope =
        residual_runtime.last_activation_scope();
    result.sealed_activation_sync_bound =
        residual_runtime.last_activation_scope_sync_binding() != Digest{} &&
        synchronized_activation_scope.session_id == scope.session_id &&
        synchronized_activation_scope.phase == scope.phase &&
        synchronized_activation_scope.round == scope.round &&
        synchronized_activation_scope.generation == scope.generation &&
        synchronized_activation_scope.checkpoint == scope.checkpoint &&
        synchronized_activation_scope.checkpoint_root == scope.checkpoint_root &&
        synchronized_activation_scope.obligations == scope.obligations &&
        synchronized_activation_scope.operations == scope.operations &&
        synchronized_activation_scope.private_operations ==
            scope.private_operations &&
        synchronized_activation_scope.transfer_operations.empty();
    if (!result.sealed_activation_sync_bound) return result;
    ReferenceShamirResidualMpcBackend& backend = residual_runtime.data_plane();
    result.runtime_bundle_bound = residual_runtime.ready_for_scope(
        synchronized_activation_scope);
    if (!result.runtime_bundle_bound ||
        !backend.HasActivatedResiduals(synchronized_activation_scope) ||
        backend.activation_binding() == Digest{})
        return result;
    result.activated_before_failure = true;
    result.activated_vss_bound = backend.HasActivatedVssProvenance(scope);
    if (!result.activated_vss_bound) return result;
    store.Clear();
    result.store_independent = store.size() == 0;
    if (!result.store_independent) return result;

    const ResidualMpcCapabilities capabilities = backend.Capabilities();
    ResidualMpcCapabilities forged = capabilities;
    forged.security_level = RobustAuditSecurityLevel::MALICIOUS_ABORT;
    forged.publicly_identifiable_abort = true;
    forged.identifiable_abort_capability_binding = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, checkpoint, 0x43415031ULL});
    forged.capability_binding = compute_residual_mpc_capability_binding(forged);
    const bool rejects_without_malicious_security =
        !validate_residual_mpc_capabilities(forged);
    forged.malicious_secure = true;
    forged.activation_before_failure = false;
    forged.capability_binding = compute_residual_mpc_capability_binding(forged);
    const bool rejects_without_failure_before_activation =
        !validate_residual_mpc_capabilities(forged);
    result.security_capability_gate_bound =
        !capabilities.malicious_secure &&
        capabilities.activation_before_failure &&
        capabilities.authenticated_channel_capability_binding != Digest{} &&
        capabilities.identifiable_abort_capability_binding == Digest{} &&
        capabilities.delivery_capability_binding == Digest{} &&
        rejects_without_malicious_security &&
        rejects_without_failure_before_activation;
    if (!validate_residual_mpc_capabilities(capabilities) ||
        capabilities.security_level !=
            RobustAuditSecurityLevel::REFERENCE_PASSIVE ||
        !result.security_capability_gate_bound)
        return result;

    MpcBackedAuthenticatedResidualProtocol passive(
        backend, RobustAuditSecurityLevel::REFERENCE_PASSIVE);
    MpcBackedAuthenticatedResidualProtocol malicious_abort(
        backend, RobustAuditSecurityLevel::MALICIOUS_ABORT);
    MpcBackedAuthenticatedResidualProtocol god(
        backend, RobustAuditSecurityLevel::MALICIOUS_GOD);
    result.passive_gate = passive.ready();
    result.malicious_abort_rejected = !malicious_abort.ready();
    result.god_rejected = !god.ready();
    if (!result.passive_gate ||
        !result.malicious_abort_rejected ||
        !result.god_rejected)
        return result;

    const Digest strong_capability_binding =
        residual_runtime.strong_consistency_capability_binding();
    const ResidualMpcMaliciousSecurityCapabilities composed_security =
        residual_runtime.security_capabilities();
    const AuthenticatedMpcAbortEvidenceCapabilities abort_security =
        make_signed_equivocation_abort_evidence_capabilities(
            capabilities.authenticated_channel_capability_binding);
    result.composed_security_provider_bound =
        validate_residual_mpc_malicious_security_capabilities(
            composed_security) &&
        composed_security.security_level ==
            RobustAuditSecurityLevel::MALICIOUS_ABORT &&
        composed_security.strong_consistency_capability_binding ==
            strong_capability_binding &&
        production_ready_authenticated_mpc_abort_evidence_capabilities(
            abort_security) &&
        composed_security.identifiable_abort_capability_binding ==
            abort_security.capability_binding &&
        !composed_security.guaranteed_output_delivery;
    if (!result.composed_security_provider_bound) return result;

    ComposedResidualMpcMaliciousAbortSecurityProvider
        detached_transport_provider(
            capabilities.implementation_binding, multiplication_backend,
            hash_words({SELFTEST_SCOPE_DOMAIN, sid, checkpoint,
                        0x4445544143484544ULL}));
    AttestedResidualMpcBackend detached_transport_backend(
        backend, detached_transport_provider,
        RobustAuditSecurityLevel::MALICIOUS_ABORT);
    MpcBackedAuthenticatedResidualProtocol detached_transport_protocol(
        detached_transport_backend,
        RobustAuditSecurityLevel::MALICIOUS_ABORT);
    result.detached_transport_scope_rejected =
        detached_transport_protocol.ready() &&
        !detached_transport_protocol.ready_for_scope(scope);
    if (!result.detached_transport_scope_rejected) return result;

    const AttestedResidualMpcBackend& attested_backend =
        residual_runtime.attested_backend();
    const MpcBackedAuthenticatedResidualProtocol& attested_protocol =
        residual_runtime.protocol();
    FailClosedResidualMpcMaliciousSecurityProvider fail_closed_provider;
    AttestedResidualMpcBackend fail_closed_backend(
        backend, fail_closed_provider,
        RobustAuditSecurityLevel::MALICIOUS_ABORT);
    MpcBackedAuthenticatedResidualProtocol fail_closed_protocol(
        fail_closed_backend, RobustAuditSecurityLevel::MALICIOUS_ABORT);
    MpcBackedAuthenticatedResidualProtocol attested_god(
        attested_backend, RobustAuditSecurityLevel::MALICIOUS_GOD);
    result.attested_malicious_gate = attested_protocol.ready();
    result.attested_scope_gate = attested_protocol.ready_for_scope(scope);
    result.failclosed_security_provider_rejected =
        !fail_closed_protocol.ready() &&
        !fail_closed_protocol.ready_for_scope(scope);
    result.attested_god_rejected = !attested_god.ready();
    if (strong_capability_binding == Digest{} ||
        !result.attested_malicious_gate ||
        !result.attested_scope_gate ||
        !result.failclosed_security_provider_rejected ||
        !result.attested_god_rejected)
        return result;

    ProtocolBackedCollectiveResidualEngine engine(passive);
    const BatchCheckResult batch =
        engine.BatchCheck(scope, local_view, rank, world_size);
    if (!batch.available || !batch.cryptographically_authenticated)
        return result;
    result.ran = true;
    result.batch_ok = batch.ok;
    result.reference_security_attestation_empty =
        batch.security_attestation_binding == Digest{};
    if (!result.reference_security_attestation_empty) return result;
    result.strong_zero_consistency = multiplication_backend.prove_count() > 0;
    if (!result.strong_zero_consistency) return result;

    const ProtocolBackedCollectiveResidualEngine& attested_engine =
        residual_runtime.engine();
    const BatchCheckResult attested_batch =
        attested_engine.BatchCheck(scope, local_view, rank, world_size);
    result.attested_batch_ok =
        attested_batch.available &&
        attested_batch.cryptographically_authenticated &&
        attested_batch.ok == batch.ok;
    result.attested_security_transcript_bound =
        attested_batch.security_attestation_binding != Digest{} &&
        validate_collective_batch_result(scope, attested_batch, world_size);
    if (!result.attested_batch_ok ||
        !result.attested_security_transcript_bound)
        return result;

    auto reject_attested_state_drift = [&]() -> bool {
        const CollectiveBatchDescriptor drift_descriptor =
            make_collective_batch_descriptor(
                scope, local_view, rank, world_size);
        const CollectiveResidualCommitmentSet drift_commitments =
            attested_backend.CommitResidualBatch(
                scope, drift_descriptor, local_view, rank, world_size);
        if (!validate_participant_commitment_set(
                scope, drift_descriptor, drift_commitments, world_size) ||
            drift_commitments.security_attestation_binding == Digest{})
            return false;
        residual_runtime.ClearActivatedResiduals();
        const bool scope_gate_rejected =
            !residual_runtime.ready_for_scope(scope);
        const AuthenticatedChallengeTranscript drift_challenge =
            attested_backend.DeriveJointChallenge(
                scope, drift_descriptor, drift_commitments, rank, world_size);
        return scope_gate_rejected &&
               !drift_challenge.available &&
               !drift_challenge.cryptographically_authenticated;
    };

    if (!inject_fault) {
        result.localized = true;
        result.attested_localized = true;
        result.attested_state_drift_rejected =
            reject_attested_state_drift();
        return result;
    }
    if (batch.ok || batch.mismatches == 0)
        return result;

    const CollectiveDisputeResult dispute =
        engine.Dispute(scope, batch, local_view, rank, world_size);
    const OperationRef expected_accused{
        faulty_owner,
        static_cast<uint64_t>(2000 + faulty_owner)};
    result.localized =
        dispute.available &&
        dispute.cryptographically_authenticated &&
        dispute.found &&
        dispute.accused == expected_accused &&
        dispute.expected != dispute.actual &&
        dispute.residual_commitment != Digest{} &&
        dispute.recursive_transcript_binding != Digest{} &&
        dispute.localization_commitment != Digest{} &&
        validate_collective_dispute_result(scope, batch, dispute);
    if (!result.localized) return result;

    const CollectiveDisputeResult attested_dispute =
        attested_engine.Dispute(
            scope, attested_batch, local_view, rank, world_size);
    result.attested_localized =
        attested_dispute.available &&
        attested_dispute.cryptographically_authenticated &&
        attested_dispute.found &&
        attested_dispute.accused == expected_accused &&
        attested_dispute.security_attestation_binding ==
            attested_batch.security_attestation_binding &&
        attested_dispute.security_attestation_binding != Digest{} &&
        attested_dispute.expected != attested_dispute.actual &&
        validate_collective_dispute_result(
            scope, attested_batch, attested_dispute);
    result.attested_state_drift_rejected =
        result.attested_localized && reject_attested_state_drift();
    return result;
}

bool run_causal_no_framing_case(int rank, int world_size) {
    if (world_size < 4 || rank < 0 || rank >= world_size) return false;

    const uint64_t sid = 0x43415553414c4e46ULL; // CAUSALNF
    const CheckpointId checkpoint = static_cast<CheckpointId>(0x7010);
    const uint32_t round = 16U;
    const uint32_t upstream_owner = 1U;
    const uint32_t downstream_owner = 2U;

    ObligationSet scope;
    scope.session_id = sid;
    scope.phase = Phase::FOLD;
    scope.round = round;
    scope.generation = 1;
    scope.exact_round = true;
    scope.checkpoint = checkpoint;
    scope.checkpoint_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, checkpoint, round, 0x43415553414cULL});
    scope.obligations = {Obligation::FOLD};
    for (int owner = 0; owner < world_size; ++owner) {
        OperationRef ref{
            static_cast<uint32_t>(owner),
            static_cast<uint64_t>(6000 + owner)};
        scope.operations.push_back(ref);
        scope.private_operations.push_back(ref);
    }

    const OperationRef upstream_ref{
        upstream_owner, static_cast<uint64_t>(6000 + upstream_owner)};
    const OperationRef downstream_ref{
        downstream_owner, static_cast<uint64_t>(6000 + downstream_owner)};

    // Reproduce Runtime::compute_predecessor_root for the downstream
    // statement, using the faulty upstream operation's authenticated actual.
    const Digest upstream_actual = hash_words({
        SELFTEST_ACTUAL_DOMAIN, sid,
        upstream_ref.owner, upstream_ref.object_id});
    const Digest upstream_predecessor_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid,
        upstream_ref.owner, upstream_ref.object_id, 0});
    std::vector<u64> predecessor_words = {
        upstream_ref.owner, upstream_ref.object_id};
    append_digest_words_selftest(upstream_actual, &predecessor_words);
    append_digest_words_selftest(
        upstream_predecessor_root, &predecessor_words);
    const Digest downstream_predecessor_root =
        hash_words(predecessor_words);

    const OperationRef local_ref{
        static_cast<uint32_t>(rank),
        static_cast<uint64_t>(6000 + rank)};
    const bool local_fault =
        static_cast<uint32_t>(rank) == upstream_owner;
    const bool is_downstream =
        static_cast<uint32_t>(rank) == downstream_owner;
    const Digest local_predecessor_root = is_downstream
        ? downstream_predecessor_root
        : hash_words({
            SELFTEST_SCOPE_DOMAIN, sid,
            local_ref.owner, local_ref.object_id, 0});
    const uint32_t local_predecessor_count =
        is_downstream ? 1U : 0U;

    PrivateResidualShareStore store;
    PrivateResidualRegistry registry;
    PrivateResidualShare local_share;
    PrivateResidualHandle local_handle;
    if (!make_authenticated_share_bound(
            sid, checkpoint, round, local_ref, local_fault,
            local_predecessor_root, local_predecessor_count,
            &local_share, &local_handle) ||
        !store.Put(local_share))
        return false;
    registry.Put(local_handle);

    const LocalResidualBatchView local_view =
        registry.BuildLocalBatchView(
            scope, static_cast<uint32_t>(rank));
    if (!local_view.complete_for_owner ||
        !local_view.all_authenticated ||
        local_view.handles.size() != 1)
        return false;

    const int threshold = (world_size - 1) / 3;
    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready()) return false;
    ReferenceShamirMpc mpc(rank, world_size, threshold);
    ReferenceShamirResidualMpcBackend backend(store, mpc, exchange);
    MpcBackedAuthenticatedResidualProtocol passive(
        backend, RobustAuditSecurityLevel::REFERENCE_PASSIVE);
    if (!passive.ready()) return false;
    ProtocolBackedCollectiveResidualEngine engine(passive);

    const BatchCheckResult batch =
        engine.BatchCheck(scope, local_view, rank, world_size);
    if (!batch.available || !batch.cryptographically_authenticated ||
        batch.ok || batch.mismatches == 0)
        return false;

    const CollectiveDisputeResult dispute =
        engine.Dispute(scope, batch, local_view, rank, world_size);
    const bool downstream_local_valid =
        !is_downstream || (
            local_share.expected == local_share.actual &&
            local_share.values.size() == 2 &&
            local_share.values[0] == F(0) &&
            local_share.values[1] == F(0));
    const bool downstream_predecessor_bound =
        !is_downstream ||
        local_share.operation_statement_binding ==
            compute_relation_statement(
                local_share.label, local_share.relation,
                local_share.kernel, local_share.expected,
                downstream_predecessor_root, 1,
                hash_words({
                    SELFTEST_SCOPE_DOMAIN, sid,
                    downstream_ref.owner,
                    downstream_ref.object_id, 1}),
                1, local_share.public_aux_root, 1);

    const bool local_ok =
        downstream_local_valid &&
        downstream_predecessor_bound &&
        dispute.available &&
        dispute.cryptographically_authenticated &&
        dispute.found &&
        dispute.accused == upstream_ref &&
        dispute.accused != downstream_ref &&
        dispute.expected != dispute.actual &&
        validate_collective_dispute_result(scope, batch, dispute);

    int local = local_ok ? 1 : 0;
    int global = 0;
    MPI_Allreduce(
        &local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (rank == 0) {
        std::cout
            << "[PVIA][causal-no-framing-selftest]"
            << " upstream=" << upstream_owner
            << " downstream=" << downstream_owner
            << " downstream-local=VALID"
            << " predecessor-bound=BOUND"
            << " mismatch=DETECTED"
            << " accused=UPSTREAM"
            << " downstream-framing=REJECTED"
            << " result=" << (global ? "PASS" : "FAIL")
            << "\n";
    }
    return global != 0;
}

bool run_tampered_preflight_case(int rank, int world_size) {
    if (world_size < 4 || rank < 0 || rank >= world_size) return false;
    const uint64_t sid = 0x52534d5043540003ULL;
    const CheckpointId checkpoint = static_cast<CheckpointId>(0x7003);
    const uint32_t round = 13U;

    ObligationSet scope;
    scope.session_id = sid;
    scope.phase = Phase::FOLD;
    scope.round = round;
    scope.generation = 1;
    scope.exact_round = true;
    scope.checkpoint = checkpoint;
    scope.checkpoint_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, checkpoint, round});
    scope.obligations = {Obligation::FOLD};
    for (int owner = 0; owner < world_size; ++owner) {
        OperationRef ref{
            static_cast<uint32_t>(owner),
            static_cast<uint64_t>(3000 + owner)};
        scope.operations.push_back(ref);
        scope.private_operations.push_back(ref);
    }

    PrivateResidualShareStore store;
    PrivateResidualRegistry registry;
    const OperationRef local_ref{
        static_cast<uint32_t>(rank),
        static_cast<uint64_t>(3000 + rank)};
    PrivateResidualShare local_share;
    PrivateResidualHandle local_handle;
    if (!make_authenticated_share(
            sid, checkpoint, round, local_ref, false,
            &local_share, &local_handle) ||
        !store.Put(local_share))
        return false;
    registry.Put(local_handle);
    LocalResidualBatchView local_view =
        registry.BuildLocalBatchView(scope, static_cast<uint32_t>(rank));
    if (!local_view.complete_for_owner || !local_view.all_authenticated ||
        local_view.handles.size() != 1)
        return false;

    // Only one rank corrupts its opaque handle after registry construction.
    // The backend must synchronize readiness and fail closed on every rank;
    // no peer may enter a later MPI collective alone.
    if (rank == 0)
        local_view.handles.front().commitment = hash_words({0xBAD0C0DEULL});

    const int threshold = (world_size - 1) / 3;
    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready()) return false;
    ReferenceShamirMpc mpc(rank, world_size, threshold);
    ReferenceShamirResidualMpcBackend backend(store, mpc, exchange);
    MpcBackedAuthenticatedResidualProtocol passive(
        backend, RobustAuditSecurityLevel::REFERENCE_PASSIVE);
    if (!passive.ready()) return false;
    ProtocolBackedCollectiveResidualEngine engine(passive);
    const BatchCheckResult batch =
        engine.BatchCheck(scope, local_view, rank, world_size);
    return !batch.available && !batch.cryptographically_authenticated;
}

} // namespace

class CountingResidualProtocol final
    : public AuthenticatedResidualProtocol {
public:
    explicit CountingResidualProtocol(
        const AuthenticatedResidualProtocol& inner)
        : inner_(inner) {}

    CollectiveResidualCommitmentSet CommitResidualBatch(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& descriptor,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const override {
        return inner_.CommitResidualBatch(
            scope, descriptor, local_view, rank, world_size);
    }

    AuthenticatedChallengeTranscript DeriveJointChallenge(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& descriptor,
        const CollectiveResidualCommitmentSet& commitments,
        int rank, int world_size) const override {
        return inner_.DeriveJointChallenge(
            scope, descriptor, commitments, rank, world_size);
    }

    BatchCheckResult RandomLinearBatchCheck(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& descriptor,
        const LocalResidualBatchView& local_view,
        const CollectiveResidualCommitmentSet& commitments,
        const AuthenticatedChallengeTranscript& transcript,
        int rank, int world_size) const override {
        return inner_.RandomLinearBatchCheck(
            scope, descriptor, local_view, commitments,
            transcript, rank, world_size);
    }

    ResidualSubsetCheckResult CheckResidualSubset(
        const ObligationSet& scope,
        const BatchCheckResult& batch,
        const ResidualSubsetDescriptor& subset,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const override {
        ++subset_checks_;
        if (subset.depth > max_depth_) max_depth_ = subset.depth;
        return inner_.CheckResidualSubset(
            scope, batch, subset, local_view, rank, world_size);
    }

    CollectiveDisputeResult FinalizeLocalization(
        const ObligationSet& scope,
        const BatchCheckResult& batch,
        const OperationRef& accused,
        const Digest& recursive_binding,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const override {
        ++finalize_calls_;
        return inner_.FinalizeLocalization(
            scope, batch, accused, recursive_binding,
            local_view, rank, world_size);
    }

    uint64_t subset_checks() const { return subset_checks_; }
    uint32_t recursive_levels() const {
        return subset_checks_ == 0 ? 0U : max_depth_ + 1U;
    }
    uint64_t finalize_calls() const { return finalize_calls_; }

private:
    const AuthenticatedResidualProtocol& inner_;
    mutable uint64_t subset_checks_ = 0;
    mutable uint32_t max_depth_ = 0;
    mutable uint64_t finalize_calls_ = 0;
};

bool run_reference_residual_localization_benchmark(
    int rank, int world_size, size_t total_operations,
    bool fault_last) {
    if (world_size < 4 || rank < 0 || rank >= world_size ||
        total_operations < static_cast<size_t>(world_size) ||
        total_operations % static_cast<size_t>(world_size) != 0)
        return false;

    const uint64_t sid = Runtime::instance().session_id();
    const uint32_t round = 31U;
    const CheckpointId checkpoint =
        (static_cast<uint64_t>(Phase::FOLD) << 56) |
        (static_cast<uint64_t>(round) << 24) |
        static_cast<uint64_t>(total_operations);

    ObligationSet scope;
    scope.session_id = sid;
    scope.phase = Phase::FOLD;
    scope.round = round;
    scope.generation = 1;
    scope.exact_round = true;
    scope.checkpoint = checkpoint;
    scope.checkpoint_root = hash_words({
        SELFTEST_SCOPE_DOMAIN, sid, checkpoint, round,
        static_cast<u64>(total_operations),
        fault_last ? 1ULL : 0ULL});
    scope.obligations = {Obligation::FOLD};

    const size_t per_owner =
        total_operations / static_cast<size_t>(world_size);
    for (int owner = 0; owner < world_size; ++owner) {
        for (size_t j = 0; j < per_owner; ++j) {
            scope.operations.push_back(OperationRef{
                static_cast<uint32_t>(owner),
                static_cast<uint64_t>(
                    800000 + static_cast<uint64_t>(owner) * 100000 + j)});
        }
    }
    scope.private_operations = scope.operations;
    const OperationRef fault_ref =
        fault_last ? scope.operations.back() : scope.operations.front();

    PrivateResidualShareStore store;
    PrivateResidualRegistry registry;
    for (size_t j = 0; j < per_owner; ++j) {
        const OperationRef ref{
            static_cast<uint32_t>(rank),
            static_cast<uint64_t>(
                800000 + static_cast<uint64_t>(rank) * 100000 + j)};
        const bool faulty = ref == fault_ref;
        PrivateResidualShare share;
        PrivateResidualHandle handle;
        if (!make_authenticated_share(
                sid, checkpoint, round, ref, faulty,
                &share, &handle) ||
            !store.Put(share))
            return false;
        registry.Put(handle);
    }

    const LocalResidualBatchView local_view =
        registry.BuildLocalBatchView(
            scope, static_cast<uint32_t>(rank));
    if (!local_view.complete_for_owner ||
        !local_view.all_authenticated ||
        local_view.handles.size() != per_owner)
        return false;

    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready()) return false;
    ReferenceShamirMpc mpc(
        rank, world_size, (world_size - 1) / 3);
    ReferenceShamirResidualMpcBackend backend(store, mpc, exchange);
    MpcBackedAuthenticatedResidualProtocol base_protocol(
        backend, RobustAuditSecurityLevel::REFERENCE_PASSIVE);
    if (!base_protocol.ready()) return false;
    CountingResidualProtocol counted(base_protocol);
    ProtocolBackedCollectiveResidualEngine engine(counted);

    const ExperimentMetricsSnapshot before =
        experiment_metrics_snapshot();
    const uint64_t batch_start = experiment_now_ns();
    const BatchCheckResult batch =
        engine.BatchCheck(scope, local_view, rank, world_size);
    const uint64_t batch_end = experiment_now_ns();
    if (!batch.available || !batch.cryptographically_authenticated ||
        batch.ok || batch.mismatches == 0)
        return false;

    const ExperimentMetricsSnapshot after_batch =
        experiment_metrics_snapshot();
    const uint64_t dispute_start = experiment_now_ns();
    const CollectiveDisputeResult dispute =
        engine.Dispute(
            scope, batch, local_view, rank, world_size);
    const uint64_t dispute_end = experiment_now_ns();
    const ExperimentMetricsSnapshot after =
        experiment_metrics_snapshot();

    const bool local_ok =
        dispute.available &&
        dispute.cryptographically_authenticated &&
        dispute.found &&
        dispute.accused == fault_ref &&
        dispute.expected != dispute.actual &&
        counted.finalize_calls() == 1 &&
        validate_collective_dispute_result(scope, batch, dispute);

    int local = local_ok ? 1 : 0;
    int global = 0;
    MPI_Allreduce(
        &local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);

    const uint64_t local_batch_ns = batch_end - batch_start;
    const uint64_t local_dispute_ns = dispute_end - dispute_start;
    uint64_t max_batch_ns = 0;
    uint64_t max_dispute_ns = 0;
    MPI_Reduce(
        &local_batch_ns, &max_batch_ns, 1, MPI_UINT64_T,
        MPI_MAX, 0, MPI_COMM_WORLD);
    MPI_Reduce(
        &local_dispute_ns, &max_dispute_ns, 1, MPI_UINT64_T,
        MPI_MAX, 0, MPI_COMM_WORLD);

    const uint64_t local_batch_auth_sent =
        after_batch.authenticated_envelope_sent_bytes -
        before.authenticated_envelope_sent_bytes;
    const uint64_t local_dispute_auth_sent =
        after.authenticated_envelope_sent_bytes -
        after_batch.authenticated_envelope_sent_bytes;
    const uint64_t local_batch_control_sent =
        after_batch.protocol_control_sent_bytes -
        before.protocol_control_sent_bytes;
    const uint64_t local_dispute_control_sent =
        after.protocol_control_sent_bytes -
        after_batch.protocol_control_sent_bytes;
    uint64_t sum_batch_auth_sent = 0;
    uint64_t sum_dispute_auth_sent = 0;
    uint64_t sum_batch_control_sent = 0;
    uint64_t sum_dispute_control_sent = 0;
    MPI_Reduce(
        &local_batch_auth_sent, &sum_batch_auth_sent,
        1, MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(
        &local_dispute_auth_sent, &sum_dispute_auth_sent,
        1, MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(
        &local_batch_control_sent, &sum_batch_control_sent,
        1, MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(
        &local_dispute_control_sent, &sum_dispute_control_sent,
        1, MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);

    uint64_t subset_min = 0, subset_max = 0;
    uint32_t depth_min = 0, depth_max = 0;
    const uint64_t local_subset = counted.subset_checks();
    const uint32_t local_depth = counted.recursive_levels();
    MPI_Reduce(
        &local_subset, &subset_min, 1, MPI_UINT64_T,
        MPI_MIN, 0, MPI_COMM_WORLD);
    MPI_Reduce(
        &local_subset, &subset_max, 1, MPI_UINT64_T,
        MPI_MAX, 0, MPI_COMM_WORLD);
    MPI_Reduce(
        &local_depth, &depth_min, 1, MPI_UNSIGNED,
        MPI_MIN, 0, MPI_COMM_WORLD);
    MPI_Reduce(
        &local_depth, &depth_max, 1, MPI_UNSIGNED,
        MPI_MAX, 0, MPI_COMM_WORLD);

    if (rank == 0) {
        const bool counters_agree =
            subset_min == subset_max && depth_min == depth_max;
        std::cout
            << "[PVIA][localization-scaling]"
            << " q=" << total_operations
            << " fault=" << (fault_last ? "last" : "first")
            << " depth=" << depth_max
            << " subset_checks=" << subset_max
            << " batch_ns=" << max_batch_ns
            << " dispute_ns=" << max_dispute_ns
            << " batch_auth_sent_bytes=" << sum_batch_auth_sent
            << " dispute_auth_sent_bytes=" << sum_dispute_auth_sent
            << " batch_control_sent_bytes=" << sum_batch_control_sent
            << " dispute_control_sent_bytes=" << sum_dispute_control_sent
            << " accused_owner=" << dispute.accused.owner
            << " accused_object=" << dispute.accused.object_id
            << " counters_agree="
            << (counters_agree ? "yes" : "no")
            << " result="
            << (global && counters_agree ? "PASS" : "FAIL")
            << "\n";
    }
    return global != 0;
}

bool run_reference_residual_mpc_selftest(
    int rank, int world_size) {
    const CaseResult clean =
        run_case(rank, world_size, false);
    const CaseResult faulty =
        run_case(rank, world_size, true);
    const bool tampered_preflight_rejected =
        run_tampered_preflight_case(rank, world_size);
    const bool causal_no_framing =
        run_causal_no_framing_case(rank, world_size);
    const ProviderCaseResult provider_clean =
        run_provider_integration_case(rank, world_size, false);
    const ProviderCaseResult provider_faulty =
        run_provider_integration_case(rank, world_size, true);
    const bool malicious_security_boundary =
        run_residual_mpc_malicious_security_boundary_selftest();

    const bool local_ok =
        clean.ran && clean.batch_ok && clean.localized &&
        clean.activated_before_failure && clean.store_independent &&
        clean.activated_vss_bound && clean.strong_zero_consistency &&
        clean.reference_security_attestation_empty &&
        clean.attested_malicious_gate && clean.attested_scope_gate &&
        clean.runtime_bundle_bound && clean.runtime_default_failclosed &&
        clean.sealed_activation_scope_bound &&
        clean.sealed_activation_local_fragment_bound &&
        clean.sealed_activation_sync_bound &&
        clean.sealed_activation_tamper_rejected &&
        clean.composed_security_provider_bound &&
        clean.detached_transport_scope_rejected &&
        clean.attested_batch_ok &&
        clean.attested_security_transcript_bound && clean.attested_localized &&
        clean.failclosed_security_provider_rejected &&
        clean.attested_god_rejected && clean.attested_state_drift_rejected &&
        clean.security_capability_gate_bound &&
        clean.passive_gate &&
        clean.malicious_abort_rejected && clean.god_rejected &&
        faulty.ran && !faulty.batch_ok && faulty.localized &&
        faulty.activated_before_failure && faulty.store_independent &&
        faulty.activated_vss_bound && faulty.strong_zero_consistency &&
        faulty.reference_security_attestation_empty &&
        faulty.attested_malicious_gate && faulty.attested_scope_gate &&
        faulty.runtime_bundle_bound && faulty.runtime_default_failclosed &&
        faulty.sealed_activation_scope_bound &&
        faulty.sealed_activation_local_fragment_bound &&
        faulty.sealed_activation_sync_bound &&
        faulty.sealed_activation_tamper_rejected &&
        faulty.composed_security_provider_bound &&
        faulty.detached_transport_scope_rejected &&
        faulty.attested_batch_ok &&
        faulty.attested_security_transcript_bound && faulty.attested_localized &&
        faulty.failclosed_security_provider_rejected &&
        faulty.attested_god_rejected && faulty.attested_state_drift_rejected &&
        faulty.security_capability_gate_bound &&
        faulty.passive_gate &&
        faulty.malicious_abort_rejected && faulty.god_rejected &&
        malicious_security_boundary && tampered_preflight_rejected &&
        causal_no_framing &&
        provider_clean.ran && provider_clean.batch_ok &&
        provider_clean.localized &&
        provider_clean.production_gate_rejected &&
        provider_faulty.ran && !provider_faulty.batch_ok &&
        provider_faulty.localized &&
        provider_faulty.production_gate_rejected;
    int local = local_ok ? 1 : 0;
    int global = 0;
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);

    if (rank == 0) {
        std::cout
            << "[PVIA][reference-residual-mpc-selftest]"
            << " clean=" << (clean.ran && clean.batch_ok ? "PASS" : "FAIL")
            << " mismatch="
            << (faulty.ran && !faulty.batch_ok ? "DETECTED" : "MISSED")
            << " localization=" << (faulty.localized ? "BOUND" : "FAIL")
            << " activated-before-failure="
            << (clean.activated_before_failure && faulty.activated_before_failure
                    ? "BOUND" : "FAIL")
            << " post-activation-store="
            << (clean.store_independent && faulty.store_independent
                    ? "INDEPENDENT" : "DEPENDENT")
            << " activated-vss="
            << (clean.activated_vss_bound && faulty.activated_vss_bound
                    ? "BOUND" : "FAIL")
            << " strong-zero-consistency="
            << (clean.strong_zero_consistency &&
                faulty.strong_zero_consistency ? "BOUND" : "FAIL")
            << " reference-security-attestation="
            << (clean.reference_security_attestation_empty &&
                faulty.reference_security_attestation_empty
                    ? "EMPTY" : "UNEXPECTED")
            << " attested-malicious="
            << (clean.attested_malicious_gate && faulty.attested_malicious_gate
                    ? "READY" : "FAIL")
            << " attested-scope-gate="
            << (clean.attested_scope_gate && faulty.attested_scope_gate
                    ? "BOUND" : "FAIL")
            << " runtime-bundle="
            << (clean.runtime_bundle_bound && faulty.runtime_bundle_bound
                    ? "BOUND" : "FAIL")
            << " runtime-default-proof="
            << (clean.runtime_default_failclosed &&
                faulty.runtime_default_failclosed
                    ? "REJECTED" : "ACCEPTED")
            << " sealed-activation-scope="
            << (clean.sealed_activation_scope_bound && faulty.sealed_activation_scope_bound
                    ? "BOUND" : "FAIL")
            << " sealed-activation-local="
            << (clean.sealed_activation_local_fragment_bound &&
                faulty.sealed_activation_local_fragment_bound
                    ? "BOUND" : "FAIL")
            << " sealed-activation-sync="
            << (clean.sealed_activation_sync_bound &&
                faulty.sealed_activation_sync_bound
                    ? "BOUND" : "FAIL")
            << " sealed-activation-tamper="
            << (clean.sealed_activation_tamper_rejected &&
                faulty.sealed_activation_tamper_rejected
                    ? "REJECTED" : "ACCEPTED")
            << " composed-malicious-provider="
            << (clean.composed_security_provider_bound &&
                faulty.composed_security_provider_bound ? "BOUND" : "FAIL")
            << " detached-transport-scope="
            << (clean.detached_transport_scope_rejected &&
                faulty.detached_transport_scope_rejected
                    ? "REJECTED" : "ACCEPTED")
            << " attested-security-transcript="
            << (clean.attested_security_transcript_bound &&
                faulty.attested_security_transcript_bound ? "BOUND" : "FAIL")
            << " attested-localization="
            << (faulty.attested_localized ? "BOUND" : "FAIL")
            << " failclosed-security-provider="
            << (clean.failclosed_security_provider_rejected &&
                faulty.failclosed_security_provider_rejected
                    ? "REJECTED" : "ACCEPTED")
            << " attested-god="
            << (clean.attested_god_rejected && faulty.attested_god_rejected
                    ? "REJECTED" : "ACCEPTED")
            << " attested-state-drift="
            << (clean.attested_state_drift_rejected &&
                faulty.attested_state_drift_rejected
                    ? "REJECTED" : "ACCEPTED")
            << " capability-contract="
            << (clean.security_capability_gate_bound &&
                faulty.security_capability_gate_bound ? "BOUND" : "FAIL")
            << " malicious-security-boundary="
            << (malicious_security_boundary ? "BOUND" : "FAIL")
            << " passive-gate=" << (faulty.passive_gate ? "READY" : "FAIL")
            << " malicious-abort="
            << (faulty.malicious_abort_rejected ? "REJECTED" : "ACCEPTED")
            << " god=" << (faulty.god_rejected ? "REJECTED" : "ACCEPTED")
            << " tamper-preflight="
            << (tampered_preflight_rejected ? "REJECTED" : "FAIL")
            << " causal-no-framing="
            << (causal_no_framing ? "BOUND" : "FAIL")
            << " provider-clean="
            << (provider_clean.ran && provider_clean.batch_ok ? "PASS" : "FAIL")
            << " provider-mismatch="
            << (provider_faulty.ran && !provider_faulty.batch_ok
                    ? "DETECTED" : "MISSED")
            << " provider-localization="
            << (provider_faulty.localized ? "BOUND" : "FAIL")
            << " provider-production-gate="
            << (provider_clean.production_gate_rejected &&
                provider_faulty.production_gate_rejected
                    ? "REJECTED" : "ACCEPTED")
            << " result=" << (global ? "PASS" : "FAIL")
            << "\n";
    }
    return global != 0;
}

} // namespace pvia
