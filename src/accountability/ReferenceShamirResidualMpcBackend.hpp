#pragma once

#include "MpcBackedAuthenticatedResidualProtocol.hpp"
#include "PrivateResidualShareStore.hpp"
#include "ReferenceShamirMpc.hpp"
#include "ReferenceBivariateVss.hpp"
#include "AuthenticatedMpcExchange.hpp"

namespace pvia {

// Development/reference implementation of the residual MPC boundary.
//
// Residual values originate in backend-owned PrivateResidualShareStore, but
// ActivateResiduals moves them into authenticated bivariate-VSS state before
// any failure-phase audit. Activated checks never re-contact the owner/store.
// This demonstrates the paper-level random-linear batch check and recursive
// localization flow, but it is intentionally REFERENCE_PASSIVE: the optional
// consistency path is still a reference/test primitive and this backend has no
// production public-abort or guaranteed-delivery construction. Stronger backends
// must carry independent malicious/abort/delivery capability bindings.
class ReferenceShamirResidualMpcBackend final : public ResidualMpcBackend {
public:
    ReferenceShamirResidualMpcBackend(
        const PrivateResidualShareStore& store,
        ReferenceShamirMpc& mpc,
        const AuthenticatedMpcExchange& exchange);

    ResidualMpcCapabilities Capabilities() const override;
    ResidualMpcPrecommitSecurityContext PrecommitSecurityContext(
        const ObligationSet& scope) const override;

    // Pre-share and snapshot all residuals before a failure is handled.
    // Once active, batch/localization never reads residual values from store_.
    bool ActivateResiduals(
        const ObligationSet& scope,
        const LocalResidualBatchView& local_view,
        int rank, int world_size);
    bool HasActivatedResiduals(const ObligationSet& scope) const;
    bool HasActivatedVssProvenance(const ObligationSet& scope) const;
    Digest activation_binding() const { return activation_binding_; }
    void ClearActivatedResiduals();

    CollectiveResidualCommitmentSet CommitResidualBatch(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& local_descriptor,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const override;

    AuthenticatedChallengeTranscript DeriveJointChallenge(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& local_descriptor,
        const CollectiveResidualCommitmentSet& commitments,
        int rank, int world_size) const override;

    BatchCheckResult RandomLinearBatchCheck(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& local_descriptor,
        const LocalResidualBatchView& local_view,
        const CollectiveResidualCommitmentSet& commitments,
        const AuthenticatedChallengeTranscript& challenge_transcript,
        int rank, int world_size) const override;

    ResidualSubsetCheckResult CheckResidualSubset(
        const ObligationSet& scope,
        const BatchCheckResult& batch,
        const ResidualSubsetDescriptor& subset,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const override;

    CollectiveDisputeResult FinalizeLocalization(
        const ObligationSet& scope,
        const BatchCheckResult& batch,
        const OperationRef& accused,
        const Digest& recursive_transcript_binding,
        const LocalResidualBatchView& local_view,
        int rank, int world_size) const override;

private:
    struct ActivatedResidualOperation {
        OperationRef ref{};
        Label label{};
        RelationKind relation = RelationKind::UNKNOWN;
        AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
        CheckpointId checkpoint = 0;
        std::vector<F> local_shares;
        Digest sharing_binding{};
        ReferenceVssLocalWitness local_witness{};
        Digest expected{};
        Digest actual{};
        Digest operation_statement_binding{};
        Digest source_commitment{};
        Digest descriptor_binding{};
    };

    bool EnsureTransport(
        const ObligationSet& scope, int rank, int world_size) const;
    bool ValidateLocalView(
        const LocalResidualBatchView& local_view, int rank) const;
    bool ValidateActivatedLocalView(
        const LocalResidualBatchView& local_view, int rank) const;
    const ActivatedResidualOperation* FindActivated(
        const OperationRef& ref) const;
    AuthenticatedMpcMessageContext NextContext(
        const ObligationSet& scope, u64 message_kind,
        uint64_t round = 0) const;
    F DeriveCoefficient(
        const Digest& challenge, const OperationRef& ref,
        size_t coordinate, const Digest& domain_binding) const;
    bool BuildFingerprint(
        const ObligationSet& scope,
        const std::vector<OperationRef>& operations,
        const Digest& challenge,
        const Digest& domain_binding,
        F* fingerprint_share,
        Digest* sharing_binding,
        ReferenceLinearSharingProvenance* provenance = nullptr) const;

    const PrivateResidualShareStore& store_;
    ReferenceShamirMpc& mpc_;
    const AuthenticatedMpcExchange& exchange_;
    mutable uint64_t active_sid_ = 0;
    mutable CheckpointId active_checkpoint_ = 0;
    mutable uint64_t exchange_sequence_ = 1;

    uint64_t activated_sid_ = 0;
    CheckpointId activated_checkpoint_ = 0;
    Digest activated_scope_binding_{};
    Digest activation_binding_{};
    std::vector<ActivatedResidualOperation> activated_operations_;
};

} // namespace pvia
