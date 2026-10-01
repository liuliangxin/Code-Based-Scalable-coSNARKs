#include "SecureAuditComposition.hpp"

#include <algorithm>
#include <utility>

namespace pvia {
namespace {

bool has_required_kernel(
    const SecureAuditComponents& components,
    AuditRelationKernel kernel) {
    if (kernel == AuditRelationKernel::UNKNOWN) return false;
    for (const KernelResidualEvaluator* evaluator :
         components.kernel_evaluators) {
        if (evaluator && evaluator->Supports(kernel)) return true;
    }
    return false;
}

} // namespace

ComposedSecureAuditProvider::ComposedSecureAuditProvider(
    SecureAuditComponents components,
    bool private_material_capture,
    RobustAuditSecurityLevel private_security_requirement)
    : components_(std::move(components)) {
    SetPrivateMaterialCapture(private_material_capture);
    SetRobustPrivateSecurityRequirement(private_security_requirement);
    if (components_.robust_session_backend)
        InstallRobustAuditSessionBackend(components_.robust_session_backend);
    if (components_.collective_engine)
        InstallCollectiveResidualEngine(components_.collective_engine);
    if (components_.transfer_engine)
        InstallPublicTransferCheckEngine(components_.transfer_engine);
    if (components_.recovery_engine)
        InstallAuthenticatedAuditRecoveryEngine(components_.recovery_engine);
    if (components_.private_blame_proof_engine)
        InstallPublicBlameProofEngine(
            components_.private_blame_proof_engine);
    if (components_.transfer_blame_proof_engine)
        InstallPublicTransferBlameProofEngine(
            components_.transfer_blame_proof_engine);

    for (const KernelResidualEvaluator* evaluator :
         components_.kernel_evaluators) {
        if (!evaluator) continue;
        InstallKernelResidualEvaluator(evaluator);
        ++installed_kernel_evaluators_;
    }
}

bool ComposedSecureAuditProvider::Ready(
    const SecureAuditRequirements& requirements) const {
    if (!requirements.private_lane && !requirements.transfer_lane)
        return false;
    if (!requirements.private_lane &&
        !requirements.required_kernels.empty())
        return false;
    if (requirements.private_lane) {
        if (requirements.private_security_level !=
                RobustAuditSecurityLevel::MALICIOUS_GOD &&
            requirements.private_security_level !=
                RobustAuditSecurityLevel::MALICIOUS_ABORT)
            return false;
        if (RobustPrivateSecurityRequirement() !=
            requirements.private_security_level)
            return false;
        bool robust_ready = false;
        RobustAuditCapabilities robust_capabilities;
        if (components_.robust_session_backend) {
            robust_capabilities = components_.robust_session_backend->Capabilities();
            robust_ready = requirements.private_security_level ==
                    RobustAuditSecurityLevel::MALICIOUS_GOD
                ? production_ready_robust_audit_capabilities(robust_capabilities)
                : production_ready_identifiable_abort_capabilities(
                    robust_capabilities);
            if (robust_ready) {
                for (AuditRelationKernel kernel : requirements.required_kernels) {
                    if (!robust_audit_supports_kernel(robust_capabilities, kernel))
                        return false;
                }
            }
        }
        const bool legacy_ready =
            requirements.private_security_level ==
                RobustAuditSecurityLevel::MALICIOUS_GOD &&
            components_.collective_engine && components_.recovery_engine &&
            components_.private_blame_proof_engine;
        if (!robust_ready && !legacy_ready) return false;
        if (!robust_ready) {
            for (AuditRelationKernel kernel : requirements.required_kernels) {
                if (!has_required_kernel(components_, kernel)) return false;
            }
        }
    }
    if (requirements.transfer_lane) {
        if (!components_.transfer_engine ||
            !components_.transfer_blame_proof_engine)
            return false;
    }
    return true;
}

void ComposedSecureAuditProvider::FinalizeInvalidMaterial(
    const AuditOperationView&) {}

void ComposedSecureAuditProvider::FinalizeUnavailableResidual(
    const AuditOperationView&, const PrivateResidualHandle&) {}

PrivateResidualHandle ComposedSecureAuditProvider::UnavailableResidual(
    const AuditOperationView& operation,
    AuditRelationKernel kernel_override) {
    PrivateResidualHandle handle;
    handle.ref = operation.ref;
    handle.label = operation.label;
    handle.relation = operation.relation;
    handle.kernel = kernel_override == AuditRelationKernel::UNKNOWN
        ? operation.kernel : kernel_override;
    handle.checkpoint = operation.checkpoint;
    return handle;
}

#define PVIA_UNAVAILABLE_RELATION_METHOD(name) \
PrivateResidualHandle ComposedSecureAuditProvider::name( \
    const AuditOperationView& operation) { \
    return UnavailableResidual(operation); \
}

PVIA_UNAVAILABLE_RELATION_METHOD(EvaluatePrivateDerivationResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateMessageBindingResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateReceiveConsumeResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateAssemblyResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateAggregationResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateCommitmentResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateFoldingResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateOpeningResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluatePublicationResidual)
PVIA_UNAVAILABLE_RELATION_METHOD(EvaluateUnsupportedResidual)

#undef PVIA_UNAVAILABLE_RELATION_METHOD

PrivateResidualHandle
ComposedSecureAuditProvider::EvaluateUnsupportedKernelResidual(
    const AuditOperationView& operation, AuditRelationKernel kernel) {
    return UnavailableResidual(operation, kernel);
}

SecureAuditRuntimeBundle::SecureAuditRuntimeBundle(
    SecureAuditComponents components,
    SecureAuditRequirements requirements)
    : provider_(std::move(components), requirements.private_lane,
                requirements.private_security_level),
      backend_(provider_),
      requirements_(std::move(requirements)) {}

SecureAuditRuntimeBundle::~SecureAuditRuntimeBundle() {
    Detach();
}

bool SecureAuditRuntimeBundle::Attach(Runtime& runtime) {
    if (!ready()) return false;
    if (runtime.audit_backend() == &backend_) {
        attached_runtime_ = &runtime;
        return true;
    }
    // Secure providers need the original private-share notifications. Runtime
    // deliberately does not retain private shares for late replay, so refuse a
    // late secure attachment instead of silently running with incomplete state.
    if (!runtime.can_attach_secure_backend()) return false;
    if (attached_runtime_ && attached_runtime_ != &runtime) Detach();
    runtime.set_audit_backend(&backend_);
    attached_runtime_ = &runtime;
    return runtime.audit_backend() == &backend_;
}

void SecureAuditRuntimeBundle::Detach() {
    if (!attached_runtime_) return;
    if (attached_runtime_->audit_backend() == &backend_)
        attached_runtime_->set_audit_backend(nullptr);
    attached_runtime_ = nullptr;
}

} // namespace pvia
