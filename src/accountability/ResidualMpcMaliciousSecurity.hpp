#pragma once

#include "MpcBackedAuthenticatedResidualProtocol.hpp"
#include "MultiplicationConsistencyProof.hpp"
#include "AuthenticatedMpcAbortEvidence.hpp"

namespace pvia {

// Independent security claim for upgrading a residual-MPC data plane beyond
// REFERENCE_PASSIVE. A concrete provider must bind its claim to one exact
// residual implementation and to a production cryptographic consistency proof.
struct ResidualMpcMaliciousSecurityCapabilities {
    bool available = false;
    uint64_t protocol_id = 0;
    RobustAuditSecurityLevel security_level =
        RobustAuditSecurityLevel::UNKNOWN;
    bool malicious_secure = false;
    bool binds_residual_implementation = false;
    bool binds_failure_before_activation = false;
    bool publicly_identifiable_abort = false;
    bool guaranteed_output_delivery = false;
    Digest residual_implementation_binding{};
    Digest strong_consistency_capability_binding{};
    Digest identifiable_abort_capability_binding{};
    Digest delivery_capability_binding{};
    Digest implementation_binding{};
    Digest capability_binding{};
};
Digest compute_residual_mpc_malicious_security_capability_binding(
    const ResidualMpcMaliciousSecurityCapabilities& capabilities);
bool validate_residual_mpc_malicious_security_capabilities(
    const ResidualMpcMaliciousSecurityCapabilities& capabilities);
bool residual_mpc_malicious_security_satisfies(
    const ResidualMpcMaliciousSecurityCapabilities& capabilities,
    RobustAuditSecurityLevel required_security);

// Scope-specific evidence that a strong security provider is attached to the
// same pre-failure activated residual state used by the collective audit.
struct ResidualMpcSecurityAttestation {
    bool available = false;
    uint64_t sid = 0;
    CheckpointId checkpoint = 0;
    RobustAuditSecurityLevel security_level =
        RobustAuditSecurityLevel::UNKNOWN;
    Digest scope_binding{};
    Digest residual_mpc_capability_binding{};
    Digest activation_binding{};
    Digest strong_consistency_capability_binding{};
    Digest identifiable_abort_capability_binding{};
    Digest delivery_capability_binding{};
    Digest security_capability_binding{};
    Digest attestation_binding{};
};
Digest compute_residual_mpc_security_attestation_binding(
    const ResidualMpcSecurityAttestation& attestation);
bool validate_residual_mpc_security_attestation(
    const ObligationSet& scope,
    const ResidualMpcCapabilities& residual_capabilities,
    const ResidualMpcMaliciousSecurityCapabilities& security_capabilities,
    const ResidualMpcSecurityAttestation& attestation,
    RobustAuditSecurityLevel required_security);

// Production boundary. Merely constructing capability structs is not enough:
// a concrete provider must create and verify the scope-specific attestation.
class ResidualMpcMaliciousSecurityProvider {
public:
    virtual ~ResidualMpcMaliciousSecurityProvider() = default;
    virtual ResidualMpcMaliciousSecurityCapabilities Capabilities() const = 0;
    virtual ResidualMpcSecurityAttestation AttestActivatedState(
        const ObligationSet& scope,
        const ResidualMpcCapabilities& residual_capabilities,
        const Digest& activation_binding,
        const Digest& strong_consistency_capability_binding) const = 0;
    virtual bool VerifyAttestation(
        const ObligationSet& scope,
        const ResidualMpcCapabilities& residual_capabilities,
        const ResidualMpcSecurityAttestation& attestation,
        RobustAuditSecurityLevel required_security) const = 0;
};
// Production MALICIOUS_ABORT composition boundary. It binds one exact
// residual implementation to a production-ready multiplication-consistency
// backend and to signed-equivocation evidence over the same authenticated
// transport. It deliberately does not claim guaranteed output delivery.
class ComposedResidualMpcMaliciousAbortSecurityProvider final
    : public ResidualMpcMaliciousSecurityProvider {
public:
    ComposedResidualMpcMaliciousAbortSecurityProvider(
        const Digest& residual_implementation_binding,
        const MultiplicationConsistencyProofBackend& consistency_backend,
        const Digest& authenticated_transport_capability_binding);

    ResidualMpcMaliciousSecurityCapabilities Capabilities() const override;
    ResidualMpcSecurityAttestation AttestActivatedState(
        const ObligationSet& scope,
        const ResidualMpcCapabilities& residual_capabilities,
        const Digest& activation_binding,
        const Digest& strong_consistency_capability_binding) const override;
    bool VerifyAttestation(
        const ObligationSet& scope,
        const ResidualMpcCapabilities& residual_capabilities,
        const ResidualMpcSecurityAttestation& attestation,
        RobustAuditSecurityLevel required_security) const override;

private:
    Digest residual_implementation_binding_{};
    const MultiplicationConsistencyProofBackend& consistency_backend_;
    Digest authenticated_transport_capability_binding_{};
};

class FailClosedResidualMpcMaliciousSecurityProvider final
    : public ResidualMpcMaliciousSecurityProvider {
public:
    ResidualMpcMaliciousSecurityCapabilities Capabilities() const override;
    ResidualMpcSecurityAttestation AttestActivatedState(
        const ObligationSet& scope,
        const ResidualMpcCapabilities& residual_capabilities,
        const Digest& activation_binding,
        const Digest& strong_consistency_capability_binding) const override;
    bool VerifyAttestation(
        const ObligationSet& scope,
        const ResidualMpcCapabilities& residual_capabilities,
        const ResidualMpcSecurityAttestation& attestation,
        RobustAuditSecurityLevel required_security) const override;
};

bool run_residual_mpc_malicious_security_boundary_selftest();

} // namespace pvia
