#pragma once

#include "AuditBackend.hpp"
#include "FoldResidualComputationBackend.hpp"
#include "PrivateAuditMaterialStore.hpp"
#include "PrivateStateMaterialStore.hpp"
#include "ReferenceShamirAuditSession.hpp"

#include <memory>

namespace pvia {

// Development-only harness for checking that real protocol instrumentation
// supplies the material required by FOLD_RS residual recomputation. It never
// participates in blame attribution and never marks residuals authenticated.
class FoldResidualRuntimeHarness final : public AuditBackend {
public:
    explicit FoldResidualRuntimeHarness(
        bool enable_reference_mpc_activation = false);

    void OnImportStateMetadata(const AuditStateView& state) override;
    void OnBindPrivateState(const AuditStateView& state,
                            const std::vector<F>& local_share) override;
    void OnRegisterOperation(const AuditOperationView& operation) override;
    void OnActivateOperation(const AuditOperationView& operation) override;
    void OnBindPrivateFieldOperation(
        const AuditOperationView& operation, AuditPrivatePayloadKind kind,
        AuditPayloadStage stage, const std::vector<F>& values) override;
    void OnBindOperationStateDependencies(
        const AuditOperationView& operation,
        const std::vector<StateId>& state_ids) override;
    void OnBindPublicFieldAux(
        const AuditOperationView& operation, AuditPublicAuxKind kind,
        const std::vector<F>& values) override;
    void OnFinalizePrivateRelation(
        const AuditOperationView& operation) override;
    void OnSealCheckpoint(const AuditCheckpointView& checkpoint) override;

    bool RunSelfCheck(int rank, int world_size) const;
    bool RunReferenceMpcSelfCheck(int rank, int world_size) const;

    BatchCheckResult BatchCheck(const ObligationSet& scope) const override;
    Violation Dispute(const ObligationSet& scope,
                      const BatchCheckResult& batch) const override;
    RecoverableAuditShare RecoverAudit(
        const Violation& violation) const override;
    BlameCertificate LiftBlame(
        const Violation& violation,
        const RecoverableAuditShare& audit) const override;
    bool Judge(const BlameCertificate& certificate,
               uint64_t expected_session_id) const override;

private:
    bool ActivateReferenceMpcCheckpoint(
        const AuditCheckpointView& checkpoint, int rank, int world_size);

    PrivateStateMaterialStore states_;
    PrivateAuditMaterialStore materials_;
    PrivateResidualShareStore shares_;
    FoldResidualComputationBackend backend_;
    size_t fold_operations_ = 0;
    size_t zero_residuals_ = 0;
    size_t nonzero_residuals_ = 0;
    size_t invalid_material_ = 0;
    std::vector<OperationRef> fold_refs_;
    bool reference_mpc_activation_enabled_ = false;
    size_t reference_mpc_activation_failures_ = 0;
    std::vector<ReferenceShamirBatchResult> reference_mpc_batches_;
    std::vector<std::unique_ptr<ReferenceShamirAuditSession>>
        reference_mpc_sessions_;
};

} // namespace pvia
