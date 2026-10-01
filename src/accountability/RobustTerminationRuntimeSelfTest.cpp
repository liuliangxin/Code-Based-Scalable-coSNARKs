#include "RobustTerminationRuntimeSelfTest.hpp"

#include "AuditBackend.hpp"
#include "AuthenticatedMpcAbortEvidence.hpp"
#include "AuthenticatedMpcExchange.hpp"
#include "RobustAuditAbortCertificateCodec.hpp"
#include "RobustAuditSession.hpp"
#include "RelationAwareSecureAuditProvider.hpp"
#include "SecureAuditComposition.hpp"
#include "TransferAuthentication.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <mpi.h>

namespace pvia {
namespace {

RobustAuditCapabilities make_runtime_verified_abort_capabilities(
    const Digest& transport_binding) {
    RobustAuditCapabilities capabilities;
    const auto abort_caps =
        make_signed_equivocation_abort_evidence_capabilities(transport_binding);
    if (!production_ready_authenticated_mpc_abort_evidence_capabilities(
            abort_caps))
        return capabilities;
    capabilities.available = true;
    capabilities.protocol_id = 0x52544d4142525431ULL; // RTMABRT1
    capabilities.security_level = RobustAuditSecurityLevel::MALICIOUS_ABORT;
    capabilities.malicious_secure = true;
    capabilities.authenticated_channels = true;
    capabilities.publicly_identifiable_abort = true;
    capabilities.guaranteed_output_delivery = false;
    capabilities.activation_before_failure = true;
    capabilities.private_witness_retention = true;
    capabilities.detectable_input_sharing = true;
    capabilities.public_registration_consistency = true;
    capabilities.robust_opening = true;
    capabilities.commit_reveal_public_coin = true;
    capabilities.detectable_degree_reduction = true;
    capabilities.detectable_random_sharing = true;
    capabilities.malicious_multiplication_consistency = true;
    capabilities.supported_kernels = {AuditRelationKernel::FOLD_RS};
    capabilities.authenticated_channel_capability_binding = transport_binding;
    capabilities.identifiable_abort_capability_binding =
        abort_caps.capability_binding;
    capabilities.registration_consistency_capability_binding =
        hash_words({0x52544d4152454743ULL, 1ULL});
    capabilities.multiplication_consistency_capability_binding =
        hash_words({0x52544d414d554c43ULL, 1ULL});
    capabilities.implementation_binding =
        hash_words({0x52544d41494d5031ULL, 1ULL});
    capabilities.capability_binding =
        compute_robust_audit_capability_binding(capabilities);
    if (!production_ready_identifiable_abort_capabilities(capabilities) ||
        production_ready_robust_audit_capabilities(capabilities))
        return RobustAuditCapabilities{};
    return capabilities;
}

bool build_runtime_verified_public_abort(
    const ObligationSet& scope, int rank, int world_size,
    RobustAuditTerminationOutput* termination,
    RobustAuditAbortCertificate* certificate) {
    if (!termination || !certificate || rank < 0 || world_size < 2 ||
        rank >= world_size || scope.session_id == 0 ||
        scope.phase == Phase::UNKNOWN || scope.checkpoint == 0 ||
        scope.checkpoint_root == Digest{})
        return false;
    auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ready() || !auth.ExternalRegistryAnchorVerified() ||
        auth.ExternalRegistryAnchor() != auth.RegistryCommitment())
        return false;
    AuthenticatedMpcExchange exchange(rank, world_size);
    const Digest transport_binding = exchange.ProductionCapabilityBinding();
    const RobustAuditCapabilities capabilities =
        make_runtime_verified_abort_capabilities(transport_binding);
    if (!production_ready_identifiable_abort_capabilities(capabilities))
        return false;

    AuditCheckpointView checkpoint;
    checkpoint.id = scope.checkpoint;
    checkpoint.phase = scope.phase;
    checkpoint.round = scope.round;
    checkpoint.generation = scope.generation;
    checkpoint.operations = scope.operations;
    checkpoint.root = scope.checkpoint_root;
    checkpoint.sealed = true;
    const uint64_t bootstrap_sid =
        compute_robust_bootstrap_transport_sid(checkpoint);
    if (bootstrap_sid == 0) return false;

    AuthenticatedMpcMessageContext context;
    context.protocol_domain = 0x52544d4142524447ULL; // RTMABRDG
    context.sid = bootstrap_sid;
    context.checkpoint = checkpoint.id;
    context.round = checkpoint.round;
    context.sequence = 1;
    context.message_kind = 0x52544d4145515631ULL; // RTMAEQV1
    std::vector<u64> gathered;
    Digest transcript{};
    if (!exchange.AllGatherWords(
            context, {static_cast<u64>(rank), 71ULL},
            &gathered, &transcript) || transcript == Digest{})
        return false;
    if (exchange.AllGatherWords(
            context, {static_cast<u64>(rank), 72ULL},
            &gathered, &transcript))
        return false;

    AuthenticatedMpcEquivocationEvidence evidence;
    if (!exchange.LastEquivocationEvidence(
            bootstrap_sid, checkpoint.id, &evidence) ||
        evidence.kind != AuthenticatedMpcAbortEvidenceKind::SIGNED_EQUIVOCATION)
        return false;
    RobustAuditAbortOutput abort;
    if (!build_robust_audit_abort_output_from_equivocation(
            checkpoint, capabilities, nullptr, evidence,
            auth.ExternalRegistryAnchor(), world_size, &abort) ||
        !validate_robust_audit_abort_output(
            checkpoint, capabilities, nullptr, abort,
            auth.ExternalRegistryAnchor(), world_size))
        return false;
    RobustAuditTerminationOutput verified_termination;
    if (!build_robust_audit_termination_from_verified_public_abort(
            checkpoint, capabilities, nullptr, abort,
            &verified_termination) ||
        !validate_robust_audit_termination_output(
            checkpoint, capabilities, nullptr, verified_termination))
        return false;

    RobustAuditAbortCertificate verified_certificate;
    verified_certificate.checkpoint = checkpoint;
    verified_certificate.capabilities = capabilities;
    verified_certificate.output = abort;
    if (!verify_robust_audit_abort_certificate(
            verified_certificate, auth.ExternalRegistryAnchor()))
        return false;
    *termination = verified_termination;
    *certificate = verified_certificate;
    return true;
}

bool build_runtime_verified_execution_abort(
    const ObligationSet& scope,
    const RobustAuditActivation& activation,
    const RobustAuditCapabilities& capabilities,
    int rank, int world_size,
    RobustAuditAbortOutput* output) {
    if (!output || rank < 0 || world_size < 2 || rank >= world_size ||
        scope.checkpoint == 0 || scope.checkpoint_root == Digest{})
        return false;
    auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ready() || !auth.ExternalRegistryAnchorVerified() ||
        auth.ExternalRegistryAnchor() != auth.RegistryCommitment())
        return false;
    AuditCheckpointView checkpoint;
    checkpoint.id = scope.checkpoint;
    checkpoint.phase = scope.phase;
    checkpoint.round = scope.round;
    checkpoint.generation = scope.generation;
    checkpoint.operations = scope.operations;
    checkpoint.root = scope.checkpoint_root;
    checkpoint.sealed = true;
    if (!validate_robust_audit_activation(
            checkpoint, capabilities, activation))
        return false;
    AuthenticatedMpcExchange exchange(rank, world_size);
    if (exchange.ProductionCapabilityBinding() !=
        capabilities.authenticated_channel_capability_binding)
        return false;
    AuthenticatedMpcMessageContext context;
    context.protocol_domain = 0x4558505542414252ULL; // EXPUBABR
    context.sid = activation.sid;
    context.checkpoint = checkpoint.id;
    context.round = checkpoint.round;
    context.sequence = 1;
    context.message_kind = 0x4558505542455156ULL; // EXPUBEQV
    std::vector<u64> gathered;
    Digest transcript{};
    if (!exchange.AllGatherWords(
            context, {static_cast<u64>(rank), 101ULL},
            &gathered, &transcript) || transcript == Digest{})
        return false;
    if (exchange.AllGatherWords(
            context, {static_cast<u64>(rank), 102ULL},
            &gathered, &transcript))
        return false;
    AuthenticatedMpcEquivocationEvidence evidence;
    if (!exchange.LastEquivocationEvidence(
            activation.sid, checkpoint.id, &evidence) ||
        evidence.kind != AuthenticatedMpcAbortEvidenceKind::SIGNED_EQUIVOCATION)
        return false;
    RobustAuditAbortOutput abort;
    if (!build_robust_audit_abort_output_from_equivocation(
            checkpoint, capabilities, &activation, evidence,
            auth.ExternalRegistryAnchor(), world_size, &abort) ||
        !validate_robust_audit_abort_output(
            checkpoint, capabilities, &activation, abort,
            auth.ExternalRegistryAnchor(), world_size))
        return false;
    *output = abort;
    return true;
}

class ActivationAbortPairBackend final : public RobustAuditSessionBackend {
public:
    ActivationAbortPairBackend(int rank, int world_size)
        : rank_(rank), world_size_(world_size) {
        AuthenticatedMpcExchange exchange(rank_, world_size_);
        capabilities_ = make_runtime_verified_abort_capabilities(
            exchange.ProductionCapabilityBinding());
    }

    RobustAuditCapabilities Capabilities() const override {
        return capabilities_;
    }

    RobustAuditActivation Activate(
        const AuditCheckpointView& checkpoint,
        const PrivateStateMaterialStore&,
        const PrivateAuditMaterialStore&) override {
        ObligationSet scope;
        scope.session_id = 0x4150435441425254ULL; // APCTABRT
        scope.phase = checkpoint.phase;
        scope.round = checkpoint.round;
        scope.generation = checkpoint.generation;
        scope.exact_round = true;
        scope.checkpoint = checkpoint.id;
        scope.checkpoint_root = checkpoint.root;
        scope.operations = checkpoint.operations;
        scope.private_operations = checkpoint.operations;
        RobustAuditTerminationOutput ignored_termination;
        RobustAuditAbortCertificate certificate;
        if (build_runtime_verified_public_abort(
                scope, rank_, world_size_, &ignored_termination,
                &certificate))
            last_abort_ = certificate.output;
        else
            last_abort_ = RobustAuditAbortOutput{};
        return {};
    }

    RobustAuditSessionOutput Execute(
        const ObligationSet&, int, int) override { return {}; }

    RobustAuditAbortOutput LastAbort() const override { return last_abort_; }

    bool VerifyPublicAbort(
        const AuditCheckpointView& checkpoint,
        const RobustAuditActivation* activation,
        const RobustAuditAbortOutput& abort) const override {
        const auto& auth = Ed25519TransferAuthenticator::instance();
        return auth.ExternalRegistryAnchorVerified() &&
            validate_robust_audit_abort_output(
                checkpoint, capabilities_, activation, abort,
                auth.ExternalRegistryAnchor(), world_size_);
    }

    bool VerifyPublicBlame(
        const PublicBlameStatement&,
        const PublicBlameProofArtifact&) const override { return false; }

private:
    int rank_ = -1;
    int world_size_ = 0;
    RobustAuditCapabilities capabilities_{};
    RobustAuditAbortOutput last_abort_{};
};

class ActivationTransportFailureBackend final
    : public RobustAuditSessionBackend {
public:
    ActivationTransportFailureBackend(int rank, int world_size)
        : rank_(rank), world_size_(world_size) {
        AuthenticatedMpcExchange exchange(rank_, world_size_);
        capabilities_ = make_runtime_verified_abort_capabilities(
            exchange.ProductionCapabilityBinding());
    }

    RobustAuditCapabilities Capabilities() const override {
        return capabilities_;
    }

    RobustAuditActivation Activate(
        const AuditCheckpointView& checkpoint,
        const PrivateStateMaterialStore&,
        const PrivateAuditMaterialStore&) override {
        failure_binding_ = Digest{};
        failure_checkpoint_ = checkpoint.id;
        AuthenticatedMpcExchange exchange(rank_, world_size_);
        const uint64_t sid = compute_robust_bootstrap_transport_sid(checkpoint);
        if (sid == 0) return {};
        AuthenticatedMpcMessageContext context;
        context.protocol_domain = 0x4150544641494c31ULL; // APTFAIL1
        context.sid = sid;
        context.checkpoint = checkpoint.id;
        context.round = checkpoint.round;
        context.sequence = 1;
        context.message_kind = 0x4150544652455031ULL; // APTFREP1
        std::vector<u64> gathered;
        Digest transcript{};
        const std::vector<u64> payload = {
            static_cast<u64>(rank_), 81ULL};
        if (!exchange.AllGatherWords(
                context, payload, &gathered, &transcript) ||
            transcript == Digest{})
            return {};
        if (exchange.AllGatherWords(
                context, payload, &gathered, &transcript))
            return {};
        AuthenticatedMpcLocalFailureObservation failure;
        if (exchange.LastLocalFailure(
                sid, checkpoint.id, &failure) &&
            failure.kind == AuthenticatedMpcLocalFailureKind::EXACT_REPLAY &&
            failure.failure_binding != Digest{})
            failure_binding_ = failure.failure_binding;
        return {};
    }

    RobustAuditSessionOutput Execute(
        const ObligationSet&, int, int) override { return {}; }

    bool LastAuthenticatedTransportFailure(
        const AuditCheckpointView& checkpoint,
        const RobustAuditActivation* activation,
        Digest* binding) const override {
        if (!binding || activation || failure_binding_ == Digest{} ||
            checkpoint.id != failure_checkpoint_)
            return false;
        *binding = failure_binding_;
        return true;
    }

    bool VerifyPublicBlame(
        const PublicBlameStatement&,
        const PublicBlameProofArtifact&) const override { return false; }

private:
    int rank_ = -1;
    int world_size_ = 0;
    RobustAuditCapabilities capabilities_{};
    Digest failure_binding_{};
    CheckpointId failure_checkpoint_ = 0;
};

class ExecutionTransportFailureBackend final
    : public RobustAuditSessionBackend {
public:
    ExecutionTransportFailureBackend(int rank, int world_size)
        : rank_(rank), world_size_(world_size) {
        AuthenticatedMpcExchange exchange(rank_, world_size_);
        capabilities_ = make_runtime_verified_abort_capabilities(
            exchange.ProductionCapabilityBinding());
    }

    RobustAuditCapabilities Capabilities() const override {
        return capabilities_;
    }

    RobustAuditActivation Activate(
        const AuditCheckpointView& checkpoint,
        const PrivateStateMaterialStore&,
        const PrivateAuditMaterialStore&) override {
        RobustAuditActivation activation;
        activation.available = true;
        activation.sid = 0x4558544653455353ULL; // EXTFSESS
        activation.checkpoint = checkpoint.id;
        activation.checkpoint_root = checkpoint.root;
        activation.checkpoint_binding =
            compute_robust_checkpoint_binding(checkpoint);
        activation.registered_operations = checkpoint.operations.size();
        activation.capability_binding = capabilities_.capability_binding;
        activation.authenticated_channel_activation_binding = hash_words({
            0x4558544641555448ULL, activation.sid}); // EXTFAUTH
        activation.registration_consistency_binding = hash_words({
            0x4558544652454743ULL, activation.sid}); // EXTFREGC
        activation.activation_transcript_binding = hash_words({
            0x4558544641435452ULL, activation.sid}); // EXTFACTR
        activation.activation_binding =
            compute_robust_audit_activation_binding(activation);
        activation_ = activation;
        return activation;
    }

    RobustAuditSessionOutput Execute(
        const ObligationSet& scope, int rank, int world_size) override {
        failure_binding_ = Digest{};
        failure_checkpoint_ = scope.checkpoint;
        if (rank != rank_ || world_size != world_size_ ||
            activation_.sid == 0 || scope.checkpoint != activation_.checkpoint)
            return {};
        AuthenticatedMpcExchange exchange(rank_, world_size_);
        AuthenticatedMpcMessageContext context;
        context.protocol_domain = 0x4558544641494c31ULL; // EXTFAIL1
        context.sid = activation_.sid;
        context.checkpoint = scope.checkpoint;
        context.round = scope.round;
        context.sequence = 1;
        context.message_kind = 0x4558544652455031ULL; // EXTFREP1
        std::vector<u64> gathered;
        Digest transcript{};
        const std::vector<u64> payload = {
            static_cast<u64>(rank_), 91ULL};
        if (!exchange.AllGatherWords(
                context, payload, &gathered, &transcript) ||
            transcript == Digest{})
            return {};
        if (exchange.AllGatherWords(
                context, payload, &gathered, &transcript))
            return {};
        AuthenticatedMpcLocalFailureObservation failure;
        if (exchange.LastLocalFailure(
                activation_.sid, scope.checkpoint, &failure) &&
            failure.kind == AuthenticatedMpcLocalFailureKind::EXACT_REPLAY &&
            failure.failure_binding != Digest{})
            failure_binding_ = failure.failure_binding;
        return {};
    }

    bool LastAuthenticatedTransportFailure(
        const AuditCheckpointView& checkpoint,
        const RobustAuditActivation* activation,
        Digest* binding) const override {
        if (!binding || !activation || failure_binding_ == Digest{} ||
            checkpoint.id != failure_checkpoint_ ||
            activation->sid != activation_.sid ||
            activation->activation_binding != activation_.activation_binding)
            return false;
        *binding = failure_binding_;
        return true;
    }

    bool VerifyPublicBlame(
        const PublicBlameStatement&,
        const PublicBlameProofArtifact&) const override { return false; }

    const RobustAuditActivation& activation() const { return activation_; }

private:
    int rank_ = -1;
    int world_size_ = 0;
    RobustAuditCapabilities capabilities_{};
    RobustAuditActivation activation_{};
    Digest failure_binding_{};
    CheckpointId failure_checkpoint_ = 0;
};

class ExecutionPublicAbortBackend final
    : public RobustAuditSessionBackend {
public:
    ExecutionPublicAbortBackend(int rank, int world_size)
        : rank_(rank), world_size_(world_size) {
        AuthenticatedMpcExchange exchange(rank_, world_size_);
        capabilities_ = make_runtime_verified_abort_capabilities(
            exchange.ProductionCapabilityBinding());
    }

    RobustAuditCapabilities Capabilities() const override {
        return capabilities_;
    }

    RobustAuditActivation Activate(
        const AuditCheckpointView& checkpoint,
        const PrivateStateMaterialStore&,
        const PrivateAuditMaterialStore&) override {
        RobustAuditActivation activation;
        activation.available = true;
        activation.sid = 0x4558505542534553ULL; // EXPUBSES
        activation.checkpoint = checkpoint.id;
        activation.checkpoint_root = checkpoint.root;
        activation.checkpoint_binding =
            compute_robust_checkpoint_binding(checkpoint);
        activation.registered_operations = checkpoint.operations.size();
        activation.capability_binding = capabilities_.capability_binding;
        activation.authenticated_channel_activation_binding = hash_words({
            0x4558505542415554ULL, activation.sid}); // EXPUBAUT
        activation.registration_consistency_binding = hash_words({
            0x4558505542524547ULL, activation.sid}); // EXPUBREG
        activation.activation_transcript_binding = hash_words({
            0x4558505542414354ULL, activation.sid}); // EXPUBACT
        activation.activation_binding =
            compute_robust_audit_activation_binding(activation);
        activation_ = activation;
        return activation;
    }

    RobustAuditSessionOutput Execute(
        const ObligationSet& scope, int rank, int world_size) override {
        last_abort_ = RobustAuditAbortOutput{};
        if (rank != rank_ || world_size != world_size_)
            return {};
        (void)build_runtime_verified_execution_abort(
            scope, activation_, capabilities_, rank_, world_size_,
            &last_abort_);
        return {};
    }

    RobustAuditAbortOutput LastAbort() const override {
        last_abort_called_ = true;
        return last_abort_;
    }

    bool VerifyPublicAbort(
        const AuditCheckpointView& checkpoint,
        const RobustAuditActivation* activation,
        const RobustAuditAbortOutput& abort) const override {
        const auto& auth = Ed25519TransferAuthenticator::instance();
        return activation && auth.ExternalRegistryAnchorVerified() &&
            validate_robust_audit_abort_output(
                checkpoint, capabilities_, activation, abort,
                auth.ExternalRegistryAnchor(), world_size_);
    }

    bool VerifyPublicBlame(
        const PublicBlameStatement&,
        const PublicBlameProofArtifact&) const override { return false; }

    const RobustAuditActivation& activation() const { return activation_; }
    bool last_abort_called() const { return last_abort_called_; }

private:
    int rank_ = -1;
    int world_size_ = 0;
    RobustAuditCapabilities capabilities_{};
    RobustAuditActivation activation_{};
    RobustAuditAbortOutput last_abort_{};
    mutable bool last_abort_called_ = false;
};

class ReconciledExecutionPublicAbortBackend final
    : public RobustAuditSessionBackend {
public:
    ReconciledExecutionPublicAbortBackend(int rank, int world_size)
        : rank_(rank), world_size_(world_size) {
        AuthenticatedMpcExchange exchange(rank_, world_size_);
        capabilities_ = make_runtime_verified_abort_capabilities(
            exchange.ProductionCapabilityBinding());
    }

    RobustAuditCapabilities Capabilities() const override {
        return capabilities_;
    }

    RobustAuditActivation Activate(
        const AuditCheckpointView& checkpoint,
        const PrivateStateMaterialStore&,
        const PrivateAuditMaterialStore&) override {
        RobustAuditActivation activation;
        activation.available = true;
        activation.sid = 0x5245434f4e534553ULL; // RECONSES
        activation.checkpoint = checkpoint.id;
        activation.checkpoint_root = checkpoint.root;
        activation.checkpoint_binding =
            compute_robust_checkpoint_binding(checkpoint);
        activation.registered_operations = checkpoint.operations.size();
        activation.capability_binding = capabilities_.capability_binding;
        activation.authenticated_channel_activation_binding = hash_words({
            0x5245434f4e415554ULL, activation.sid}); // RECONAUT
        activation.registration_consistency_binding = hash_words({
            0x5245434f4e524547ULL, activation.sid}); // RECONREG
        activation.activation_transcript_binding = hash_words({
            0x5245434f4e414354ULL, activation.sid}); // RECONACT
        activation.activation_binding =
            compute_robust_audit_activation_binding(activation);
        activation_ = activation;
        return activation;
    }

    RobustAuditSessionOutput Execute(
        const ObligationSet&, int rank, int world_size) override {
        execute_called_ = true;
        if (rank != rank_ || world_size != world_size_)
            execute_rank_mismatch_ = true;
        return {};
    }

    RobustAuditAbortOutput ReconcileAbortCollectively(
        const AuditCheckpointView& checkpoint,
        const RobustAuditActivation* activation,
        int rank, int world_size) override {
        reconcile_called_ = true;
        if (!activation || rank != rank_ || world_size != world_size_ ||
            activation->activation_binding != activation_.activation_binding)
            return {};
        ObligationSet scope;
        scope.session_id = activation->sid;
        scope.phase = checkpoint.phase;
        scope.round = checkpoint.round;
        scope.generation = checkpoint.generation;
        scope.exact_round = true;
        scope.checkpoint = checkpoint.id;
        scope.checkpoint_root = checkpoint.root;
        scope.operations = checkpoint.operations;
        scope.private_operations = checkpoint.operations;
        RobustAuditAbortOutput abort;
        if (!build_runtime_verified_execution_abort(
                scope, *activation, capabilities_, rank_, world_size_, &abort))
            return {};
        reconciled_abort_ = abort;
        return abort;
    }

    RobustAuditAbortOutput LastAbort() const override {
        last_abort_called_ = true;
        return {};
    }

    bool VerifyPublicAbort(
        const AuditCheckpointView& checkpoint,
        const RobustAuditActivation* activation,
        const RobustAuditAbortOutput& abort) const override {
        const auto& auth = Ed25519TransferAuthenticator::instance();
        return activation && auth.ExternalRegistryAnchorVerified() &&
            validate_robust_audit_abort_output(
                checkpoint, capabilities_, activation, abort,
                auth.ExternalRegistryAnchor(), world_size_);
    }

    bool VerifyPublicBlame(
        const PublicBlameStatement&,
        const PublicBlameProofArtifact&) const override { return false; }

    const RobustAuditActivation& activation() const { return activation_; }
    bool execute_called() const { return execute_called_; }
    bool execute_rank_mismatch() const { return execute_rank_mismatch_; }
    bool reconcile_called() const { return reconcile_called_; }
    bool last_abort_called() const { return last_abort_called_; }

private:
    int rank_ = -1;
    int world_size_ = 0;
    RobustAuditCapabilities capabilities_{};
    RobustAuditActivation activation_{};
    RobustAuditAbortOutput reconciled_abort_{};
    bool execute_called_ = false;
    bool execute_rank_mismatch_ = false;
    bool reconcile_called_ = false;
    mutable bool last_abort_called_ = false;
};

class AttachedBundleDualModeBackend final
    : public RobustAuditSessionBackend {
public:
    AttachedBundleDualModeBackend(int rank, int world_size)
        : rank_(rank), world_size_(world_size) {
        AuthenticatedMpcExchange exchange(rank_, world_size_);
        capabilities_ = make_runtime_verified_abort_capabilities(
            exchange.ProductionCapabilityBinding());
    }

    RobustAuditCapabilities Capabilities() const override {
        return capabilities_;
    }

    RobustAuditActivation Activate(
        const AuditCheckpointView& checkpoint,
        const PrivateStateMaterialStore&,
        const PrivateAuditMaterialStore&) override {
        RobustAuditActivation activation;
        activation.available = true;
        activation.sid = 0x42554e444c455345ULL ^ checkpoint.id;
        if (activation.sid == 0) activation.sid = checkpoint.id | 1ULL;
        activation.checkpoint = checkpoint.id;
        activation.checkpoint_root = checkpoint.root;
        activation.checkpoint_binding =
            compute_robust_checkpoint_binding(checkpoint);
        activation.registered_operations = checkpoint.operations.size();
        activation.capability_binding = capabilities_.capability_binding;
        activation.authenticated_channel_activation_binding = hash_words({
            0x42554e444c454155ULL, activation.sid});
        activation.registration_consistency_binding = hash_words({
            0x42554e444c455245ULL, activation.sid});
        activation.activation_transcript_binding = hash_words({
            0x42554e444c454143ULL, activation.sid});
        activation.activation_binding =
            compute_robust_audit_activation_binding(activation);
        activation_ = activation;
        return activation;
    }

    RobustAuditSessionOutput Execute(
        const ObligationSet& scope, int rank, int world_size) override {
        last_abort_ = RobustAuditAbortOutput{};
        failure_binding_ = Digest{};
        failure_checkpoint_ = scope.checkpoint;
        if (rank != rank_ || world_size != world_size_ ||
            activation_.sid == 0 || scope.checkpoint != activation_.checkpoint)
            return {};
        if (scope.round == 11) {
            (void)build_runtime_verified_execution_abort(
                scope, activation_, capabilities_, rank_, world_size_,
                &last_abort_);
            return {};
        }
        if (scope.round != 12) return {};
        AuthenticatedMpcExchange exchange(rank_, world_size_);
        AuthenticatedMpcMessageContext context;
        context.protocol_domain = 0x42554e4452455031ULL;
        context.sid = activation_.sid;
        context.checkpoint = scope.checkpoint;
        context.round = scope.round;
        context.sequence = 1;
        context.message_kind = 0x42554e4452455032ULL;

        std::vector<u64> gathered;
        Digest transcript{};
        const std::vector<u64> payload = {
            static_cast<u64>(rank_), 121ULL};
        if (!exchange.AllGatherWords(
                context, payload, &gathered, &transcript) ||
            transcript == Digest{})
            return {};
        if (exchange.AllGatherWords(
                context, payload, &gathered, &transcript))
            return {};
        AuthenticatedMpcLocalFailureObservation failure;
        if (exchange.LastLocalFailure(
                activation_.sid, scope.checkpoint, &failure) &&
            failure.kind == AuthenticatedMpcLocalFailureKind::EXACT_REPLAY &&
            failure.failure_binding != Digest{})
            failure_binding_ = failure.failure_binding;
        return {};
    }

    RobustAuditAbortOutput LastAbort() const override {
        return last_abort_;
    }

    bool LastAuthenticatedTransportFailure(
        const AuditCheckpointView& checkpoint,
        const RobustAuditActivation* activation,
        Digest* binding) const override {
        if (!binding || !activation || failure_binding_ == Digest{} ||
            checkpoint.id != failure_checkpoint_ ||
            activation->sid != activation_.sid ||
            activation->activation_binding != activation_.activation_binding)
            return false;
        *binding = failure_binding_;
        return true;
    }

    bool VerifyPublicAbort(
        const AuditCheckpointView& checkpoint,
        const RobustAuditActivation* activation,
        const RobustAuditAbortOutput& abort) const override {
        const auto& auth = Ed25519TransferAuthenticator::instance();
        return activation && auth.ExternalRegistryAnchorVerified() &&
            validate_robust_audit_abort_output(
                checkpoint, capabilities_, activation, abort,
                auth.ExternalRegistryAnchor(), world_size_);
    }

    bool VerifyPublicBlame(
        const PublicBlameStatement&,
        const PublicBlameProofArtifact&) const override { return false; }

private:
    int rank_ = -1;
    int world_size_ = 0;
    RobustAuditCapabilities capabilities_{};
    RobustAuditActivation activation_{};
    RobustAuditAbortOutput last_abort_{};
    Digest failure_binding_{};
    CheckpointId failure_checkpoint_ = 0;
};

class TerminationStatusOnlyBackend final : public AuditBackend {
public:
    TerminationStatusOnlyBackend() {
        termination_.available = true;
        termination_.kind =
            RobustAuditTerminationKind::DETECTABLE_UNATTRIBUTABLE_ABORT;
        termination_.stage = RobustAuditAbortStage::EXECUTION;
        termination_.unattributable_reason =
            RobustAuditUnattributableAbortReason::EXECUTION_UNAVAILABLE;
        termination_.authenticated_route = true;
        termination_.detectable_abort = true;
        termination_.publicly_attributable = false;
    }

    bool RequiresCollectiveFailureHandling() const override { return true; }
    bool GetLastRobustTermination(
        RobustAuditTerminationOutput* output) const override {
        if (!output || last_checkpoint_ == 0) return false;
        *output = termination_;
        output->checkpoint = last_checkpoint_;
        return true;
    }

    BatchCheckResult BatchCheck(const ObligationSet& scope) const override {
        last_checkpoint_ = scope.checkpoint;
        BatchCheckResult result;
        result.available = false;
        result.ok = false;
        result.checkpoint = scope.checkpoint;
        return result;
    }

    Violation Dispute(
        const ObligationSet&, const BatchCheckResult&) const override {
        blame_path_called_ = true;
        return Violation{};
    }

    RecoverableAuditShare RecoverAudit(
        const Violation&) const override {
        blame_path_called_ = true;
        return RecoverableAuditShare{};
    }
    BlameCertificate LiftBlame(
        const Violation&, const RecoverableAuditShare&) const override {
        blame_path_called_ = true;
        return BlameCertificate{};
    }

    bool Judge(
        const BlameCertificate&, uint64_t) const override {
        blame_path_called_ = true;
        return false;
    }

    bool blame_path_called() const { return blame_path_called_; }

private:
    RobustAuditTerminationOutput termination_{};
    mutable CheckpointId last_checkpoint_ = 0;
    mutable bool blame_path_called_ = false;
};

class ScopeSubstitutionBackend final : public AuditBackend {
public:
    bool RequiresCollectiveFailureHandling() const override { return true; }
    ObligationSet SynchronizeFailureScope(
        const ObligationSet& local_scope, int, int) const override {
        ObligationSet substituted = local_scope;
        substituted.checkpoint ^= 1ULL;
        if (substituted.checkpoint == 0) substituted.checkpoint = 1;
        return substituted;
    }
    BatchCheckResult BatchCheck(const ObligationSet& scope) const override {
        batch_called_ = true;
        BatchCheckResult result;
        result.available = false;
        result.ok = false;
        result.checkpoint = scope.checkpoint;
        return result;
    }
    Violation Dispute(
        const ObligationSet&, const BatchCheckResult&) const override {
        blame_path_called_ = true;
        return Violation{};
    }
    RecoverableAuditShare RecoverAudit(const Violation&) const override {
        blame_path_called_ = true;
        return RecoverableAuditShare{};
    }
    BlameCertificate LiftBlame(
        const Violation&, const RecoverableAuditShare&) const override {
        blame_path_called_ = true;
        return BlameCertificate{};
    }
    bool Judge(const BlameCertificate&, uint64_t) const override {
        blame_path_called_ = true;
        return false;
    }
    bool batch_called() const { return batch_called_; }
    bool blame_path_called() const { return blame_path_called_; }

private:
    mutable bool batch_called_ = false;
    mutable bool blame_path_called_ = false;
};

class UnverifiedPublicAbortStatusBackend final : public AuditBackend {
public:
    UnverifiedPublicAbortStatusBackend() {
        termination_.available = true;
        termination_.kind =
            RobustAuditTerminationKind::PUBLICLY_ATTRIBUTABLE_ABORT;
        termination_.stage = RobustAuditAbortStage::EXECUTION;
        termination_.authenticated_route = true;
        termination_.detectable_abort = true;
        termination_.publicly_attributable = true;
        termination_.public_abort_binding.bytes[0] = 1;
    }
    bool RequiresCollectiveFailureHandling() const override { return true; }
    bool GetLastRobustTermination(
        RobustAuditTerminationOutput* output) const override {
        if (!output || last_checkpoint_ == 0) return false;
        *output = termination_;
        output->checkpoint = last_checkpoint_;
        return true;
    }
    bool GetLastRobustAbortCertificate(
        RobustAuditAbortCertificate*) const override {
        certificate_requested_ = true;
        return false;
    }
    BatchCheckResult BatchCheck(const ObligationSet& scope) const override {
        last_checkpoint_ = scope.checkpoint;
        BatchCheckResult result;
        result.available = false;
        result.ok = false;
        result.checkpoint = scope.checkpoint;
        return result;
    }
    Violation Dispute(
        const ObligationSet&, const BatchCheckResult&) const override {
        blame_path_called_ = true;
        return Violation{};
    }
    RecoverableAuditShare RecoverAudit(const Violation&) const override {
        blame_path_called_ = true;
        return RecoverableAuditShare{};
    }
    BlameCertificate LiftBlame(
        const Violation&, const RecoverableAuditShare&) const override {
        blame_path_called_ = true;
        return BlameCertificate{};
    }
    bool Judge(const BlameCertificate&, uint64_t) const override {
        blame_path_called_ = true;
        return false;
    }
    bool certificate_requested() const { return certificate_requested_; }
    bool blame_path_called() const { return blame_path_called_; }

private:
    RobustAuditTerminationOutput termination_{};
    mutable CheckpointId last_checkpoint_ = 0;
    mutable bool certificate_requested_ = false;
    mutable bool blame_path_called_ = false;
};

class VerifiedPublicAbortBackend final : public AuditBackend {
public:
    VerifiedPublicAbortBackend(int rank, int world_size)
        : rank_(rank), world_size_(world_size) {}

    bool RequiresCollectiveFailureHandling() const override { return true; }
    bool GetLastRobustTermination(
        RobustAuditTerminationOutput* output) const override {
        if (!output || !ready_) return false;
        *output = termination_;
        return true;
    }
    bool GetLastRobustAbortCertificate(
        RobustAuditAbortCertificate* certificate) const override {
        certificate_requested_ = true;
        if (!certificate || !ready_) return false;
        *certificate = certificate_;
        return true;
    }
    BatchCheckResult BatchCheck(const ObligationSet& scope) const override {
        ready_ = build_runtime_verified_public_abort(
            scope, rank_, world_size_, &termination_, &certificate_);
        BatchCheckResult result;
        result.available = false;
        result.ok = false;
        result.checkpoint = scope.checkpoint;
        return result;
    }
    Violation Dispute(
        const ObligationSet&, const BatchCheckResult&) const override {
        blame_path_called_ = true;
        return Violation{};
    }
    RecoverableAuditShare RecoverAudit(const Violation&) const override {
        blame_path_called_ = true;
        return RecoverableAuditShare{};
    }
    BlameCertificate LiftBlame(
        const Violation&, const RecoverableAuditShare&) const override {
        blame_path_called_ = true;
        return BlameCertificate{};
    }
    bool Judge(const BlameCertificate&, uint64_t) const override {
        blame_path_called_ = true;
        return false;
    }
    bool ready() const { return ready_; }
    bool certificate_requested() const { return certificate_requested_; }
    bool blame_path_called() const { return blame_path_called_; }

private:
    int rank_ = -1;
    int world_size_ = 0;
    mutable bool ready_ = false;
    mutable bool certificate_requested_ = false;
    mutable bool blame_path_called_ = false;
    mutable RobustAuditTerminationOutput termination_{};
    mutable RobustAuditAbortCertificate certificate_{};
};

bool run_provider_activation_abort_pair_selftest(int rank, int world_size) {
    const auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ExternalRegistryAnchorVerified() ||
        auth.ExternalRegistryAnchor() != auth.RegistryCommitment())
        return false;

    ActivationAbortPairBackend robust_backend(rank, world_size);
    if (!production_ready_identifiable_abort_capabilities(
            robust_backend.Capabilities()))
        return false;
    SecureAuditComponents components;
    components.robust_session_backend = &robust_backend;
    ComposedSecureAuditProvider provider(
        components, true, RobustAuditSecurityLevel::MALICIOUS_ABORT);

    AuditOperationView operation;
    operation.ref = OperationRef{0, 0x415043544f503031ULL}; // APCTOP01
    operation.label.sid = 0x4150435453455353ULL; // APCTSESS
    operation.label.phase = Phase::FOLD;
    operation.label.round = 6;
    operation.label.owner = 0;
    operation.label.obligation = Obligation::FOLD;
    operation.label.object_id = operation.ref.object_id;
    operation.relation = RelationKind::FOLDING;
    operation.kernel = AuditRelationKernel::FOLD_RS;
    operation.active = true;

    AuditCheckpointView checkpoint;
    checkpoint.id = 0x41504354434b5031ULL; // APCTCKP1
    checkpoint.phase = Phase::FOLD;
    checkpoint.round = 6;
    checkpoint.generation = 1;
    checkpoint.operations = {operation.ref};
    checkpoint.root = hash_words({
        0x41504354524f4f54ULL, checkpoint.id, checkpoint.round});
    checkpoint.sealed = true;
    operation.checkpoint = checkpoint.id;
    provider.RegisterOperation(operation);
    provider.SealCheckpoint(checkpoint);

    RobustAuditTerminationOutput before_termination;
    RobustAuditAbortCertificate before_certificate;
    const bool before_ok =
        provider.GetLastRobustTermination(&before_termination) &&
        before_termination.kind ==
            RobustAuditTerminationKind::PUBLICLY_ATTRIBUTABLE_ABORT &&
        before_termination.stage == RobustAuditAbortStage::ACTIVATION &&
        provider.GetLastRobustAbortCertificate(&before_certificate) &&
        verify_robust_audit_abort_certificate(
            before_certificate, auth.ExternalRegistryAnchor());

    ObligationSet scope;
    scope.session_id = operation.label.sid;
    scope.phase = checkpoint.phase;
    scope.round = checkpoint.round;
    scope.generation = checkpoint.generation;
    scope.exact_round = true;
    scope.checkpoint = checkpoint.id;
    scope.checkpoint_root = checkpoint.root;
    scope.obligations = {Obligation::FOLD};
    scope.operations = checkpoint.operations;
    scope.private_operations = checkpoint.operations;
    const BatchCheckResult unavailable = provider.PrivateBatchCheck(scope);

    RobustAuditTerminationOutput after_termination;
    RobustAuditAbortCertificate after_certificate;
    const bool preserved_ok = !unavailable.available &&
        provider.GetLastRobustTermination(&after_termination) &&
        provider.GetLastRobustAbortCertificate(&after_certificate) &&
        after_termination.checkpoint == checkpoint.id &&
        after_termination.public_abort_binding ==
            before_termination.public_abort_binding &&
        after_certificate.output.abort_binding ==
            before_certificate.output.abort_binding &&
        verify_robust_audit_abort_certificate(
            after_certificate, auth.ExternalRegistryAnchor());

    ObligationSet next_scope = scope;
    next_scope.checkpoint ^= 1ULL;
    if (next_scope.checkpoint == 0) next_scope.checkpoint = 1;
    next_scope.checkpoint_root = hash_words({
        0x415043544e455854ULL, next_scope.checkpoint});
    (void)provider.PrivateBatchCheck(next_scope);
    RobustAuditTerminationOutput stale_termination;
    RobustAuditAbortCertificate stale_certificate;
    const bool stale_cleared =
        !provider.GetLastRobustTermination(&stale_termination) &&
        !provider.GetLastRobustAbortCertificate(&stale_certificate);
    return before_ok && preserved_ok && stale_cleared;
}

bool run_provider_activation_transport_failure_selftest(
    int rank, int world_size) {
    const auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ExternalRegistryAnchorVerified() ||
        auth.ExternalRegistryAnchor() != auth.RegistryCommitment())
        return false;

    ActivationTransportFailureBackend robust_backend(rank, world_size);
    if (!production_ready_identifiable_abort_capabilities(
            robust_backend.Capabilities()))
        return false;
    SecureAuditComponents components;
    components.robust_session_backend = &robust_backend;
    ComposedSecureAuditProvider provider(
        components, true, RobustAuditSecurityLevel::MALICIOUS_ABORT);

    AuditOperationView operation;
    operation.ref = OperationRef{0, 0x415054464f503031ULL}; // APTFOP01
    operation.label.sid = 0x4150544653455353ULL; // APTFSESS
    operation.label.phase = Phase::FOLD;
    operation.label.round = 7;
    operation.label.owner = 0;
    operation.label.obligation = Obligation::FOLD;
    operation.label.object_id = operation.ref.object_id;
    operation.relation = RelationKind::FOLDING;
    operation.kernel = AuditRelationKernel::FOLD_RS;
    operation.active = true;

    AuditCheckpointView checkpoint;
    checkpoint.id = 0x41505446434b5031ULL; // APTFCKP1
    checkpoint.phase = Phase::FOLD;
    checkpoint.round = 7;
    checkpoint.generation = 1;
    checkpoint.operations = {operation.ref};
    checkpoint.root = hash_words({
        0x41505446524f4f54ULL, checkpoint.id, checkpoint.round});
    checkpoint.sealed = true;
    operation.checkpoint = checkpoint.id;
    provider.RegisterOperation(operation);
    provider.SealCheckpoint(checkpoint);

    RobustAuditTerminationOutput before_termination;
    RobustAuditAbortCertificate forbidden_certificate;
    const bool before_ok =
        provider.GetLastRobustTermination(&before_termination) &&
        before_termination.kind ==
            RobustAuditTerminationKind::DETECTABLE_UNATTRIBUTABLE_ABORT &&
        before_termination.stage == RobustAuditAbortStage::ACTIVATION &&
        before_termination.unattributable_reason ==
            RobustAuditUnattributableAbortReason::AUTHENTICATED_TRANSPORT_FAILURE &&
        before_termination.authenticated_route &&
        before_termination.detectable_abort &&
        !before_termination.publicly_attributable &&
        before_termination.public_abort_binding == Digest{} &&
        before_termination.local_failure_binding != Digest{} &&
        !provider.GetLastRobustAbortCertificate(&forbidden_certificate);

    ObligationSet scope;
    scope.session_id = operation.label.sid;
    scope.phase = checkpoint.phase;
    scope.round = checkpoint.round;
    scope.generation = checkpoint.generation;
    scope.exact_round = true;
    scope.checkpoint = checkpoint.id;
    scope.checkpoint_root = checkpoint.root;
    scope.obligations = {Obligation::FOLD};
    scope.operations = checkpoint.operations;
    scope.private_operations = checkpoint.operations;
    const BatchCheckResult unavailable = provider.PrivateBatchCheck(scope);

    RobustAuditTerminationOutput after_termination;
    RobustAuditAbortCertificate after_certificate;
    const bool preserved_ok = !unavailable.available &&
        provider.GetLastRobustTermination(&after_termination) &&
        after_termination.kind ==
            RobustAuditTerminationKind::DETECTABLE_UNATTRIBUTABLE_ABORT &&
        after_termination.unattributable_reason ==
            RobustAuditUnattributableAbortReason::AUTHENTICATED_TRANSPORT_FAILURE &&
        after_termination.termination_binding ==
            before_termination.termination_binding &&
        after_termination.local_failure_binding ==
            before_termination.local_failure_binding &&
        after_termination.public_abort_binding == Digest{} &&
        !after_termination.publicly_attributable &&
        !provider.GetLastRobustAbortCertificate(&after_certificate);

    ObligationSet next_scope = scope;
    next_scope.checkpoint ^= 1ULL;
    if (next_scope.checkpoint == 0) next_scope.checkpoint = 1;
    next_scope.checkpoint_root = hash_words({
        0x415054464e455854ULL, next_scope.checkpoint});
    (void)provider.PrivateBatchCheck(next_scope);
    RobustAuditTerminationOutput stale_termination;
    RobustAuditAbortCertificate stale_certificate;
    const bool stale_cleared =
        !provider.GetLastRobustTermination(&stale_termination) &&
        !provider.GetLastRobustAbortCertificate(&stale_certificate);
    return before_ok && preserved_ok && stale_cleared;
}

bool run_provider_execution_transport_failure_selftest(
    int rank, int world_size) {
    const auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ExternalRegistryAnchorVerified() ||
        auth.ExternalRegistryAnchor() != auth.RegistryCommitment())
        return false;

    ExecutionTransportFailureBackend robust_backend(rank, world_size);
    if (!production_ready_identifiable_abort_capabilities(
            robust_backend.Capabilities()))
        return false;
    SecureAuditComponents components;
    components.robust_session_backend = &robust_backend;
    ComposedSecureAuditProvider provider(
        components, true, RobustAuditSecurityLevel::MALICIOUS_ABORT);

    AuditOperationView operation;
    operation.ref = OperationRef{0, 0x455854464f503031ULL}; // EXTFOP01
    operation.label.sid = 0x4558544653455353ULL; // EXTFSESS
    operation.label.phase = Phase::FOLD;
    operation.label.round = 8;
    operation.label.owner = 0;
    operation.label.obligation = Obligation::FOLD;
    operation.label.object_id = operation.ref.object_id;
    operation.relation = RelationKind::FOLDING;
    operation.kernel = AuditRelationKernel::FOLD_RS;
    operation.active = true;

    AuditCheckpointView checkpoint;
    checkpoint.id = 0x45585446434b5031ULL; // EXTFCKP1
    checkpoint.phase = Phase::FOLD;
    checkpoint.round = 8;
    checkpoint.generation = 1;
    checkpoint.operations = {operation.ref};
    checkpoint.root = hash_words({
        0x45585446524f4f54ULL, checkpoint.id, checkpoint.round});
    checkpoint.sealed = true;
    operation.checkpoint = checkpoint.id;
    provider.RegisterOperation(operation);
    provider.SealCheckpoint(checkpoint);

    RobustAuditTerminationOutput premature_termination;
    RobustAuditAbortCertificate premature_certificate;
    const bool activation_ok =
        validate_robust_audit_activation(
            checkpoint, robust_backend.Capabilities(),
            robust_backend.activation()) &&
        !provider.GetLastRobustTermination(&premature_termination) &&
        !provider.GetLastRobustAbortCertificate(&premature_certificate);

    ObligationSet scope;
    scope.session_id = operation.label.sid;
    scope.phase = checkpoint.phase;
    scope.round = checkpoint.round;
    scope.generation = checkpoint.generation;
    scope.exact_round = true;
    scope.checkpoint = checkpoint.id;
    scope.checkpoint_root = checkpoint.root;
    scope.obligations = {Obligation::FOLD};
    scope.operations = checkpoint.operations;
    scope.private_operations = checkpoint.operations;
    const ObligationSet synchronized_scope =
        provider.SynchronizeFailureScope(scope, rank, world_size);
    const bool scope_sync_ok =
        synchronized_scope.session_id == scope.session_id &&
        synchronized_scope.checkpoint == scope.checkpoint &&
        synchronized_scope.checkpoint_root == scope.checkpoint_root &&
        synchronized_scope.generation == scope.generation &&
        synchronized_scope.operations == scope.operations &&
        synchronized_scope.private_operations == scope.private_operations;
    const BatchCheckResult unavailable =
        provider.PrivateBatchCheck(synchronized_scope);

    RobustAuditTerminationOutput termination;
    RobustAuditAbortCertificate forbidden_certificate;
    const bool failure_ok = scope_sync_ok && !unavailable.available &&
        provider.GetLastRobustTermination(&termination) &&
        termination.kind ==
            RobustAuditTerminationKind::DETECTABLE_UNATTRIBUTABLE_ABORT &&
        termination.stage == RobustAuditAbortStage::EXECUTION &&
        termination.unattributable_reason ==
            RobustAuditUnattributableAbortReason::AUTHENTICATED_TRANSPORT_FAILURE &&
        termination.sid == robust_backend.activation().sid &&
        termination.activation_binding ==
            robust_backend.activation().activation_binding &&
        termination.authenticated_route && termination.detectable_abort &&
        !termination.publicly_attributable &&
        termination.public_abort_binding == Digest{} &&
        termination.local_failure_binding != Digest{} &&
        validate_robust_audit_termination_output(
            checkpoint, robust_backend.Capabilities(),
            &robust_backend.activation(), termination) &&
        !provider.GetLastRobustAbortCertificate(&forbidden_certificate);

    ObligationSet next_scope = scope;
    next_scope.checkpoint ^= 1ULL;
    if (next_scope.checkpoint == 0) next_scope.checkpoint = 1;
    next_scope.checkpoint_root = hash_words({
        0x455854464e455854ULL, next_scope.checkpoint});
    (void)provider.PrivateBatchCheck(next_scope);
    RobustAuditTerminationOutput stale_termination;
    RobustAuditAbortCertificate stale_certificate;
    const bool stale_cleared =
        !provider.GetLastRobustTermination(&stale_termination) &&
        !provider.GetLastRobustAbortCertificate(&stale_certificate);
    return activation_ok && failure_ok && stale_cleared;
}

bool run_provider_execution_public_abort_selftest(
    int rank, int world_size) {
    const auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ExternalRegistryAnchorVerified() ||
        auth.ExternalRegistryAnchor() != auth.RegistryCommitment())
        return false;

    ExecutionPublicAbortBackend robust_backend(rank, world_size);
    if (!production_ready_identifiable_abort_capabilities(
            robust_backend.Capabilities()))
        return false;
    SecureAuditComponents components;
    components.robust_session_backend = &robust_backend;
    ComposedSecureAuditProvider provider(
        components, true, RobustAuditSecurityLevel::MALICIOUS_ABORT);
    SecureAuditBackend secure_backend(provider);

    AuditOperationView operation;
    operation.ref = OperationRef{0, 0x455850554f503031ULL}; // EXPUBOP1
    operation.label.sid = 0x4558505542534553ULL; // EXPUBSES
    operation.label.phase = Phase::FOLD;
    operation.label.round = 9;
    operation.label.owner = 0;
    operation.label.obligation = Obligation::FOLD;
    operation.label.object_id = operation.ref.object_id;
    operation.relation = RelationKind::FOLDING;
    operation.kernel = AuditRelationKernel::FOLD_RS;
    operation.active = true;

    AuditCheckpointView checkpoint;
    checkpoint.id = 0x45585055434b5031ULL; // EXPUBCK1
    checkpoint.phase = Phase::FOLD;
    checkpoint.round = 9;
    checkpoint.generation = 1;
    checkpoint.operations = {operation.ref};
    checkpoint.root = hash_words({
        0x4558505542524f54ULL, checkpoint.id, checkpoint.round});
    checkpoint.sealed = true;
    operation.checkpoint = checkpoint.id;
    secure_backend.OnRegisterOperation(operation);
    secure_backend.OnSealCheckpoint(checkpoint);

    RobustAuditTerminationOutput premature_termination;
    RobustAuditAbortCertificate premature_certificate;
    const bool activation_ok =
        validate_robust_audit_activation(
            checkpoint, robust_backend.Capabilities(),
            robust_backend.activation()) &&
        !secure_backend.GetLastRobustTermination(&premature_termination) &&
        !secure_backend.GetLastRobustAbortCertificate(&premature_certificate);

    ObligationSet scope;
    scope.session_id = operation.label.sid;
    scope.phase = checkpoint.phase;
    scope.round = checkpoint.round;
    scope.generation = checkpoint.generation;
    scope.exact_round = true;
    scope.checkpoint = checkpoint.id;
    scope.checkpoint_root = checkpoint.root;
    scope.obligations = {Obligation::FOLD};
    scope.operations = checkpoint.operations;
    scope.private_operations = checkpoint.operations;
    const ObligationSet synchronized_scope =
        secure_backend.SynchronizeFailureScope(scope, rank, world_size);
    const bool scope_sync_ok =
        synchronized_scope.session_id == scope.session_id &&
        synchronized_scope.checkpoint == scope.checkpoint &&
        synchronized_scope.checkpoint_root == scope.checkpoint_root &&
        synchronized_scope.operations == scope.operations &&
        synchronized_scope.private_operations == scope.private_operations;
    const BatchCheckResult unavailable =
        secure_backend.BatchCheck(synchronized_scope);

    RobustAuditTerminationOutput termination;
    RobustAuditAbortCertificate certificate;
    const bool public_ok = scope_sync_ok && !unavailable.available &&
        robust_backend.last_abort_called() &&
        secure_backend.GetLastRobustTermination(&termination) &&
        termination.kind ==
            RobustAuditTerminationKind::PUBLICLY_ATTRIBUTABLE_ABORT &&
        termination.stage == RobustAuditAbortStage::EXECUTION &&
        termination.publicly_attributable &&
        termination.local_failure_binding == Digest{} &&
        termination.public_abort_binding != Digest{} &&
        secure_backend.GetLastRobustAbortCertificate(&certificate) &&
        certificate.has_activation &&
        certificate.activation.activation_binding ==
            robust_backend.activation().activation_binding &&
        certificate.output.abort_binding == termination.public_abort_binding &&
        certificate.output.stage == RobustAuditAbortStage::EXECUTION &&
        verify_robust_audit_abort_certificate(
            certificate, auth.ExternalRegistryAnchor());

    ObligationSet next_scope = scope;
    next_scope.checkpoint ^= 1ULL;
    if (next_scope.checkpoint == 0) next_scope.checkpoint = 1;
    next_scope.checkpoint_root = hash_words({
        0x455850554e455854ULL, next_scope.checkpoint});
    (void)secure_backend.BatchCheck(next_scope);
    RobustAuditTerminationOutput stale_termination;
    RobustAuditAbortCertificate stale_certificate;
    const bool stale_cleared =
        !secure_backend.GetLastRobustTermination(&stale_termination) &&
        !secure_backend.GetLastRobustAbortCertificate(&stale_certificate);
    return activation_ok && public_ok && stale_cleared;
}

bool run_provider_reconciled_execution_abort_selftest(
    int rank, int world_size) {
    const auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ExternalRegistryAnchorVerified() ||
        auth.ExternalRegistryAnchor() != auth.RegistryCommitment())
        return false;

    ReconciledExecutionPublicAbortBackend robust_backend(rank, world_size);
    if (!production_ready_identifiable_abort_capabilities(
            robust_backend.Capabilities()))
        return false;
    SecureAuditComponents components;
    components.robust_session_backend = &robust_backend;
    ComposedSecureAuditProvider provider(
        components, true, RobustAuditSecurityLevel::MALICIOUS_ABORT);

    AuditOperationView operation;
    operation.ref = OperationRef{0, 0x5245434f4f503031ULL}; // RECOOP01
    operation.label.sid = 0x5245434f4e534553ULL; // RECONSES
    operation.label.phase = Phase::FOLD;
    operation.label.round = 10;
    operation.label.owner = 0;
    operation.label.obligation = Obligation::FOLD;
    operation.label.object_id = operation.ref.object_id;
    operation.relation = RelationKind::FOLDING;
    operation.kernel = AuditRelationKernel::FOLD_RS;
    operation.active = true;

    AuditCheckpointView checkpoint;
    checkpoint.id = 0x5245434f434b5031ULL; // RECOCKP1
    checkpoint.phase = Phase::FOLD;
    checkpoint.round = 10;
    checkpoint.generation = 1;
    checkpoint.operations = {operation.ref};
    checkpoint.root = hash_words({
        0x5245434f4e524f54ULL, checkpoint.id, checkpoint.round});
    checkpoint.sealed = true;
    operation.checkpoint = checkpoint.id;
    provider.RegisterOperation(operation);
    provider.SealCheckpoint(checkpoint);

    RobustAuditTerminationOutput premature_termination;
    RobustAuditAbortCertificate premature_certificate;
    const bool activation_ok =
        validate_robust_audit_activation(
            checkpoint, robust_backend.Capabilities(),
            robust_backend.activation()) &&
        !provider.GetLastRobustTermination(&premature_termination) &&
        !provider.GetLastRobustAbortCertificate(&premature_certificate);

    ObligationSet scope;
    scope.session_id = operation.label.sid;
    scope.phase = checkpoint.phase;
    scope.round = checkpoint.round;
    scope.generation = checkpoint.generation;
    scope.exact_round = true;
    scope.checkpoint = checkpoint.id;
    scope.checkpoint_root = checkpoint.root;
    scope.obligations = {Obligation::FOLD};
    scope.operations = checkpoint.operations;
    scope.private_operations = checkpoint.operations;
    const ObligationSet synchronized_scope =
        provider.SynchronizeFailureScope(scope, rank, world_size);
    const bool scope_sync_ok =
        synchronized_scope.checkpoint == scope.checkpoint &&
        synchronized_scope.checkpoint_root == scope.checkpoint_root &&
        synchronized_scope.operations == scope.operations &&
        synchronized_scope.private_operations == scope.private_operations;
    const BatchCheckResult unavailable =
        provider.PrivateBatchCheck(synchronized_scope);

    RobustAuditTerminationOutput termination;
    RobustAuditAbortCertificate certificate;
    const bool public_ok = scope_sync_ok && !unavailable.available &&
        robust_backend.execute_called() &&
        !robust_backend.execute_rank_mismatch() &&
        robust_backend.reconcile_called() &&
        !robust_backend.last_abort_called() &&
        provider.GetLastRobustTermination(&termination) &&
        termination.kind ==
            RobustAuditTerminationKind::PUBLICLY_ATTRIBUTABLE_ABORT &&
        termination.stage == RobustAuditAbortStage::EXECUTION &&
        termination.local_failure_binding == Digest{} &&
        termination.public_abort_binding != Digest{} &&
        provider.GetLastRobustAbortCertificate(&certificate) &&
        certificate.has_activation &&
        certificate.activation.activation_binding ==
            robust_backend.activation().activation_binding &&
        certificate.output.abort_binding == termination.public_abort_binding &&
        verify_robust_audit_abort_certificate(
            certificate, auth.ExternalRegistryAnchor());

    ObligationSet next_scope = scope;
    next_scope.checkpoint ^= 1ULL;
    if (next_scope.checkpoint == 0) next_scope.checkpoint = 1;
    next_scope.checkpoint_root = hash_words({
        0x5245434f4e455854ULL, next_scope.checkpoint});
    (void)provider.PrivateBatchCheck(next_scope);
    RobustAuditTerminationOutput stale_termination;
    RobustAuditAbortCertificate stale_certificate;
    const bool stale_cleared =
        !provider.GetLastRobustTermination(&stale_termination) &&
        !provider.GetLastRobustAbortCertificate(&stale_certificate);
    return activation_ok && public_ok && stale_cleared;
}

bool run_attached_secure_bundle_runtime_benchmark_scenario(
    Runtime& runtime, int rank, int world_size, bool public_abort) {
    auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ExternalRegistryAnchorVerified() ||
        auth.ExternalRegistryAnchor() != auth.RegistryCommitment())
        return false;
    if (!runtime.can_attach_secure_backend() || runtime.audit_backend())
        return false;

    AttachedBundleDualModeBackend robust_backend(rank, world_size);
    SecureAuditComponents components;
    components.robust_session_backend = &robust_backend;
    SecureAuditRequirements requirements;
    requirements.private_lane = true;
    requirements.transfer_lane = false;
    requirements.private_security_level =
        RobustAuditSecurityLevel::MALICIOUS_ABORT;
    requirements.required_kernels = {AuditRelationKernel::FOLD_RS};
    SecureAuditRuntimeBundle bundle(components, requirements);
    if (!bundle.ready() || !bundle.Attach(runtime) ||
        runtime.audit_backend() != &bundle.backend())
        return false;

    const uint32_t round = public_abort ? 11U : 12U;
    const std::vector<u64> words = public_abort
        ? std::vector<u64>{111ULL, 222ULL}
        : std::vector<u64>{333ULL, 444ULL};
    std::array<u64, META_WORDS> meta{};
    if (rank == 0) {
        const RecordId id = runtime.register_word_operation(
            Phase::FOLD, round, Obligation::FOLD, words, {});
        if (id == 0) return false;
        runtime.bind_relation_kernel(id, AuditRelationKernel::FOLD_RS);
        runtime.activate_words(id, words);
        meta = runtime.make_pending_meta(words);
    }
    MPI_Bcast(meta.data(), META_WORDS, MPI_UINT64_T, 0, MPI_COMM_WORLD);
    if (rank == 0) runtime.observe_outgoing_transfer(meta, words);
    else runtime.observe_remote_meta(0, meta, words);
    runtime.seal_checkpoint_instance(Phase::FOLD, round);
    const bool handled = runtime.handle_global_failure(
        public_abort ? "final_codeword_attached_public_abort_benchmark"
                     : "final_codeword_attached_replay_abort_benchmark",
        Phase::FOLD, round);

    bool scenario_ok = !handled && !runtime.has_failure();
    if (public_abort) {
        RobustAuditAbortCertificate certificate;
        if (rank == 0) {
            scenario_ok = scenario_ok && runtime.has_robust_abort_certificate() &&
                runtime.robust_abort_registry_anchor() ==
                    auth.ExternalRegistryAnchor() &&
                runtime.latest_robust_abort_certificate(&certificate) &&
                certificate.has_activation &&
                certificate.output.stage == RobustAuditAbortStage::EXECUTION &&
                verify_robust_audit_abort_certificate(
                    certificate, auth.ExternalRegistryAnchor());
        } else {
            scenario_ok = scenario_ok && !runtime.has_robust_abort_certificate();
        }
    } else {
        RobustAuditTerminationOutput termination;
        RobustAuditAbortCertificate forbidden_certificate;
        scenario_ok = scenario_ok &&
            !runtime.has_robust_abort_certificate() &&
            bundle.backend().GetLastRobustTermination(&termination) &&
            termination.kind ==
                RobustAuditTerminationKind::DETECTABLE_UNATTRIBUTABLE_ABORT &&
            termination.stage == RobustAuditAbortStage::EXECUTION &&
            termination.unattributable_reason ==
                RobustAuditUnattributableAbortReason::AUTHENTICATED_TRANSPORT_FAILURE &&
            termination.local_failure_binding != Digest{} &&
            termination.public_abort_binding == Digest{} &&
            !termination.publicly_attributable &&
            !bundle.backend().GetLastRobustAbortCertificate(
                &forbidden_certificate);
    }

    bundle.Detach();
    scenario_ok = scenario_ok && runtime.audit_backend() == nullptr;
    int local = scenario_ok ? 1 : 0;
    int global = 0;
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (rank == 0)
        std::cout << "[PVIA][robust-termination-runtime-benchmark] mode="
                  << (public_abort ? "attached-public" : "attached-replay")
                  << " result=" << (global ? "PASS" : "FAIL") << "\n";
    return global != 0;
}

bool run_attached_secure_bundle_runtime_selftest(
    Runtime& runtime, int rank, int world_size) {

    auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ExternalRegistryAnchorVerified() ||
        auth.ExternalRegistryAnchor() != auth.RegistryCommitment())
        return true;
    if (!runtime.can_attach_secure_backend() || runtime.audit_backend())
        return false;

    AttachedBundleDualModeBackend robust_backend(rank, world_size);
    SecureAuditComponents components;
    components.robust_session_backend = &robust_backend;
    SecureAuditRequirements requirements;
    requirements.private_lane = true;
    requirements.transfer_lane = false;
    requirements.private_security_level =
        RobustAuditSecurityLevel::MALICIOUS_ABORT;
    requirements.required_kernels = {AuditRelationKernel::FOLD_RS};
    SecureAuditRuntimeBundle bundle(components, requirements);
    if (!bundle.ready() || !bundle.Attach(runtime) ||
        runtime.audit_backend() != &bundle.backend())
        return false;

    const std::vector<u64> public_words = {111ULL, 222ULL};
    std::array<u64, META_WORDS> public_meta{};
    if (rank == 0) {
        const RecordId public_id = runtime.register_word_operation(
            Phase::FOLD, 11, Obligation::FOLD, public_words, {});
        if (public_id == 0) return false;
        runtime.bind_relation_kernel(public_id, AuditRelationKernel::FOLD_RS);
        runtime.activate_words(public_id, public_words);
        public_meta = runtime.make_pending_meta(public_words);
    }
    MPI_Bcast(public_meta.data(), META_WORDS, MPI_UINT64_T, 0, MPI_COMM_WORLD);
    if (rank == 0) runtime.observe_outgoing_transfer(public_meta, public_words);
    else runtime.observe_remote_meta(0, public_meta, public_words);
    runtime.seal_checkpoint_instance(Phase::FOLD, 11);
    const bool public_handled = runtime.handle_global_failure(
        "final_codeword_attached_public_abort_selftest", Phase::FOLD, 11);
    RobustAuditAbortCertificate public_certificate;
    bool public_ok = !public_handled && !runtime.has_failure();
    if (rank == 0) {
        public_ok = public_ok && runtime.has_robust_abort_certificate() &&
            runtime.robust_abort_registry_anchor() ==
                auth.ExternalRegistryAnchor() &&
            runtime.latest_robust_abort_certificate(&public_certificate) &&
            public_certificate.has_activation &&
            public_certificate.output.stage == RobustAuditAbortStage::EXECUTION &&
            verify_robust_audit_abort_certificate(
                public_certificate, auth.ExternalRegistryAnchor());
    } else {
        public_ok = public_ok && !runtime.has_robust_abort_certificate();
    }

    const std::vector<u64> local_words = {333ULL, 444ULL};
    std::array<u64, META_WORDS> local_meta{};
    if (rank == 0) {
        const RecordId local_id = runtime.register_word_operation(
            Phase::FOLD, 12, Obligation::FOLD, local_words, {});
        if (local_id == 0) return false;
        runtime.bind_relation_kernel(local_id, AuditRelationKernel::FOLD_RS);
        runtime.activate_words(local_id, local_words);
        local_meta = runtime.make_pending_meta(local_words);
    }
    MPI_Bcast(local_meta.data(), META_WORDS, MPI_UINT64_T, 0, MPI_COMM_WORLD);
    if (rank == 0) runtime.observe_outgoing_transfer(local_meta, local_words);
    else runtime.observe_remote_meta(0, local_meta, local_words);
    runtime.seal_checkpoint_instance(Phase::FOLD, 12);
    const bool local_handled = runtime.handle_global_failure(
        "final_codeword_attached_local_failure_selftest", Phase::FOLD, 12);
    RobustAuditTerminationOutput local_termination;
    RobustAuditAbortCertificate forbidden_certificate;
    const bool local_ok = !local_handled && !runtime.has_failure() &&
        !runtime.has_robust_abort_certificate() &&
        bundle.backend().GetLastRobustTermination(&local_termination) &&
        local_termination.kind ==
            RobustAuditTerminationKind::DETECTABLE_UNATTRIBUTABLE_ABORT &&
        local_termination.stage == RobustAuditAbortStage::EXECUTION &&
        local_termination.unattributable_reason ==
            RobustAuditUnattributableAbortReason::AUTHENTICATED_TRANSPORT_FAILURE &&
        local_termination.local_failure_binding != Digest{} &&
        local_termination.public_abort_binding == Digest{} &&
        !local_termination.publicly_attributable &&
        !bundle.backend().GetLastRobustAbortCertificate(
            &forbidden_certificate);

    bundle.Detach();
    const bool detached = runtime.audit_backend() == nullptr;

    if (rank == 0 && public_ok && local_ok && detached)
        std::cout << "[PVIA][robust-termination-runtime-selftest] "
                  << "attached-bundle-public=BOUND "
                  << "attached-bundle-local-failure=UNATTRIBUTABLE "
                  << "attached-bundle-stale-clear=BOUND\n";
    return public_ok && local_ok && detached;
}

} // namespace

bool run_robust_termination_runtime_selftest(
    Runtime& runtime, int rank, int world_size) {
    if (!runtime.enabled() || rank < 0 || world_size <= 0 ||
        rank >= world_size || runtime.rank() != rank ||
        runtime.world_size() != world_size || runtime.has_failure())
        return false;
    const char* benchmark_mode_env =
        std::getenv("PVIA_ROBUST_TERMINATION_RUNTIME_SELFTEST_MODE");
    const std::string benchmark_mode = benchmark_mode_env
        ? std::string(benchmark_mode_env) : std::string();
    if (benchmark_mode == "attached-public")
        return run_attached_secure_bundle_runtime_benchmark_scenario(
            runtime, rank, world_size, true);
    if (benchmark_mode == "attached-replay")
        return run_attached_secure_bundle_runtime_benchmark_scenario(
            runtime, rank, world_size, false);
    if (!benchmark_mode.empty() && benchmark_mode != "full")
        return false;

    const bool attached_bundle_ok =
        run_attached_secure_bundle_runtime_selftest(runtime, rank, world_size);
    TerminationStatusOnlyBackend backend;
    const bool handled = runtime.handle_global_failure_with_backend(
        "robust-termination-runtime-selftest", Phase::INIT, 0, backend);
    const bool termination_ok = !handled && !runtime.has_failure() &&
        !backend.blame_path_called();

    ScopeSubstitutionBackend substitution_backend;
    const bool substitution_handled =
        runtime.handle_global_failure_with_backend(
            "robust-scope-substitution-selftest", Phase::INIT, 1,
            substitution_backend);
    const bool substitution_ok = !substitution_handled &&
        !runtime.has_failure() && !substitution_backend.batch_called() &&
        !substitution_backend.blame_path_called();

    UnverifiedPublicAbortStatusBackend public_backend;
    const bool public_handled = runtime.handle_global_failure_with_backend(
        "robust-public-abort-status-selftest", Phase::INIT, 2,
        public_backend);
    const bool public_status_ok = !public_handled &&
        !runtime.has_failure() && !public_backend.blame_path_called() &&
        public_backend.certificate_requested() == (rank == 0);

    bool verified_public_ok = true;
    bool retained_artifact_ok = !runtime.has_robust_abort_certificate();
    bool stale_clear_ok = true;
    bool restored_artifact_ok = true;
    bool provider_activation_pair_ok = true;
    bool provider_activation_transport_failure_ok = true;
    bool provider_execution_transport_failure_ok = true;
    bool provider_execution_public_abort_ok = true;
    bool provider_reconciled_execution_abort_ok = true;
    auto& auth = Ed25519TransferAuthenticator::instance();
    if (auth.ExternalRegistryAnchorVerified() &&
        auth.ExternalRegistryAnchor() == auth.RegistryCommitment()) {
        VerifiedPublicAbortBackend verified_backend(rank, world_size);
        const bool verified_public_handled =
            runtime.handle_global_failure_with_backend(
                "robust-verified-public-abort-selftest", Phase::FOLD, 3,
                verified_backend);
        verified_public_ok = !verified_public_handled &&
            !runtime.has_failure() && verified_backend.ready() &&
            !verified_backend.blame_path_called() &&
            verified_backend.certificate_requested() == (rank == 0);
        if (rank == 0) {
            RobustAuditAbortCertificate retained_certificate;
            retained_artifact_ok =
                runtime.has_robust_abort_certificate() &&
                runtime.robust_abort_registry_anchor() ==
                    auth.ExternalRegistryAnchor() &&
                runtime.latest_robust_abort_certificate(
                    &retained_certificate) &&
                verify_robust_audit_abort_certificate(
                    retained_certificate, auth.ExternalRegistryAnchor());
        } else {
            retained_artifact_ok = !runtime.has_robust_abort_certificate();
        }

        TerminationStatusOnlyBackend stale_clear_backend;
        const bool stale_clear_handled =
            runtime.handle_global_failure_with_backend(
                "robust-artifact-stale-clear-selftest", Phase::INIT, 4,
                stale_clear_backend);
        stale_clear_ok = !stale_clear_handled && !runtime.has_failure() &&
            !runtime.has_robust_abort_certificate() &&
            !stale_clear_backend.blame_path_called();

        VerifiedPublicAbortBackend restored_backend(rank, world_size);
        const bool restored_handled = runtime.handle_global_failure_with_backend(
            "robust-artifact-restore-selftest", Phase::FOLD, 5,
            restored_backend);
        restored_artifact_ok = !restored_handled && !runtime.has_failure() &&
            restored_backend.ready() && !restored_backend.blame_path_called() &&
            restored_backend.certificate_requested() == (rank == 0);
        if (rank == 0) {
            RobustAuditAbortCertificate restored_certificate;
            restored_artifact_ok = restored_artifact_ok &&
                runtime.has_robust_abort_certificate() &&
                runtime.robust_abort_registry_anchor() ==
                    auth.ExternalRegistryAnchor() &&
                runtime.latest_robust_abort_certificate(
                    &restored_certificate) &&
                verify_robust_audit_abort_certificate(
                    restored_certificate, auth.ExternalRegistryAnchor());
        } else {
            restored_artifact_ok = restored_artifact_ok &&
                !runtime.has_robust_abort_certificate();
        }
        provider_activation_pair_ok =
            run_provider_activation_abort_pair_selftest(rank, world_size);
        provider_activation_transport_failure_ok =
            run_provider_activation_transport_failure_selftest(
                rank, world_size);
        provider_execution_transport_failure_ok =
            run_provider_execution_transport_failure_selftest(
                rank, world_size);
        provider_execution_public_abort_ok =
            run_provider_execution_public_abort_selftest(
                rank, world_size);
        provider_reconciled_execution_abort_ok =
            run_provider_reconciled_execution_abort_selftest(
                rank, world_size);
        if (rank == 0 && verified_public_ok && retained_artifact_ok &&
            stale_clear_ok && restored_artifact_ok &&
            provider_activation_pair_ok &&
            provider_activation_transport_failure_ok &&
            provider_execution_transport_failure_ok &&
            provider_execution_public_abort_ok &&
            provider_reconciled_execution_abort_ok)
            std::cout << "[PVIA][robust-termination-runtime-selftest] "
                      << "verified-public-abort=BOUND retained=BOUND "
                      << "stale-clear=BOUND restored=BOUND "
                      << "activation-pair=BOUND "
                      << "activation-local-failure=UNATTRIBUTABLE "
                      << "execution-local-failure=UNATTRIBUTABLE "
                      << "execution-public-abort=BOUND "
                      << "reconciled-public-abort=BOUND\n";
    }

    const bool local_ok = attached_bundle_ok && termination_ok &&
        substitution_ok &&
        public_status_ok && verified_public_ok && retained_artifact_ok &&
        stale_clear_ok && restored_artifact_ok &&
        provider_activation_pair_ok &&
        provider_activation_transport_failure_ok &&
        provider_execution_transport_failure_ok &&
        provider_execution_public_abort_ok &&
        provider_reconciled_execution_abort_ok;
    int local = local_ok ? 1 : 0;
    int global = 0;
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    return global != 0;
}

} // namespace pvia
