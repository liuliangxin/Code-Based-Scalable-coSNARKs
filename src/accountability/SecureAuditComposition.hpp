#pragma once

#include "RelationAwareSecureAuditProvider.hpp"
#include "RobustAuditSession.hpp"

#include <vector>

namespace pvia {

struct SecureAuditRequirements {
    bool private_lane = true;
    bool transfer_lane = true;
    RobustAuditSecurityLevel private_security_level =
        RobustAuditSecurityLevel::MALICIOUS_GOD;
    std::vector<AuditRelationKernel> required_kernels;
};

struct SecureAuditComponents {
    RobustAuditSessionBackend* robust_session_backend = nullptr;
    const CollectiveResidualEngine* collective_engine = nullptr;
    const PublicTransferCheckEngine* transfer_engine = nullptr;
    const AuthenticatedAuditRecoveryEngine* recovery_engine = nullptr;
    const PublicBlameProofEngine* private_blame_proof_engine = nullptr;
    const PublicTransferBlameProofEngine* transfer_blame_proof_engine = nullptr;
    std::vector<const KernelResidualEvaluator*> kernel_evaluators;
    RobustAuditSessionBackend* robust_private_session = nullptr;
};

// Safe concrete composition point for externally supplied cryptographic
// engines. Missing relation-specific implementations remain unavailable rather
// than falling back to cleartext or unauthenticated local checks.
class ComposedSecureAuditProvider final
    : public RelationAwareSecureAuditProvider {
public:
    explicit ComposedSecureAuditProvider(
        SecureAuditComponents components,
        bool private_material_capture = true,
        RobustAuditSecurityLevel private_security_requirement =
            RobustAuditSecurityLevel::MALICIOUS_GOD);

    bool Ready(const SecureAuditRequirements& requirements) const;
    const SecureAuditComponents& components() const { return components_; }

protected:
    void FinalizeInvalidMaterial(
        const AuditOperationView& operation) override;
    void FinalizeUnavailableResidual(
        const AuditOperationView& operation,
        const PrivateResidualHandle& handle) override;

    PrivateResidualHandle EvaluatePrivateDerivationResidual(
        const AuditOperationView& operation) override;
    PrivateResidualHandle EvaluateMessageBindingResidual(
        const AuditOperationView& operation) override;
    PrivateResidualHandle EvaluateReceiveConsumeResidual(
        const AuditOperationView& operation) override;
    PrivateResidualHandle EvaluateAssemblyResidual(
        const AuditOperationView& operation) override;
    PrivateResidualHandle EvaluateAggregationResidual(
        const AuditOperationView& operation) override;
    PrivateResidualHandle EvaluateCommitmentResidual(
        const AuditOperationView& operation) override;
    PrivateResidualHandle EvaluateFoldingResidual(
        const AuditOperationView& operation) override;
    PrivateResidualHandle EvaluateOpeningResidual(
        const AuditOperationView& operation) override;
    PrivateResidualHandle EvaluatePublicationResidual(
        const AuditOperationView& operation) override;
    PrivateResidualHandle EvaluateUnsupportedResidual(
        const AuditOperationView& operation) override;
    PrivateResidualHandle EvaluateUnsupportedKernelResidual(
        const AuditOperationView& operation,
        AuditRelationKernel kernel) override;

private:
    static PrivateResidualHandle UnavailableResidual(
        const AuditOperationView& operation,
        AuditRelationKernel kernel_override = AuditRelationKernel::UNKNOWN);

    SecureAuditComponents components_;
    size_t installed_kernel_evaluators_ = 0;
};

class SecureAuditRuntimeBundle {
public:
    SecureAuditRuntimeBundle(
        SecureAuditComponents components,
        SecureAuditRequirements requirements = {});
    ~SecureAuditRuntimeBundle();
    SecureAuditRuntimeBundle(const SecureAuditRuntimeBundle&) = delete;
    SecureAuditRuntimeBundle& operator=(const SecureAuditRuntimeBundle&) = delete;
    SecureAuditRuntimeBundle(SecureAuditRuntimeBundle&&) = delete;
    SecureAuditRuntimeBundle& operator=(SecureAuditRuntimeBundle&&) = delete;
    bool ready() const { return provider_.Ready(requirements_); }
    bool Attach(Runtime& runtime);
    void Detach();

    ComposedSecureAuditProvider& provider() { return provider_; }
    const ComposedSecureAuditProvider& provider() const { return provider_; }
    SecureAuditBackend& backend() { return backend_; }
    const SecureAuditBackend& backend() const { return backend_; }

private:
    ComposedSecureAuditProvider provider_;
    SecureAuditBackend backend_;
    SecureAuditRequirements requirements_;
    Runtime* attached_runtime_ = nullptr;
};

} // namespace pvia
