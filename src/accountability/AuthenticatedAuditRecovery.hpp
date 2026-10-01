#pragma once

#include "PVIA.hpp"

namespace pvia {

struct AuthenticatedRecoveryRequest {
    Label label{};
    CheckpointId checkpoint = 0;
    RelationKind relation = RelationKind::UNKNOWN;
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    Digest expected{};
    Digest actual{};
    Digest residual_commitment{};
    Digest operation_statement_binding{};
    Digest dispute_binding{};
    Digest checkpoint_root{};
    Digest request_binding{};
};

struct AuthenticatedRecoveryArtifact {
    bool available = false;
    bool cryptographically_authenticated = false;
    OperationRef accused{};
    CheckpointId checkpoint = 0;
    RelationKind relation = RelationKind::UNKNOWN;
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    Digest request_binding{};
    Digest operation_statement_binding{};
    Digest dispute_binding{};
    Digest predecessor_root{};
    Digest checkpoint_root{};
    Digest recovered_audit_commitment{};
    Digest recovery_transcript_binding{};
    Digest authentication_proof_commitment{};
};

Digest compute_recovery_request_binding(
    const AuthenticatedRecoveryRequest& request);
AuthenticatedRecoveryRequest make_recovery_request(
    const Violation& violation,
    const AuditCheckpointView& checkpoint);
Digest compute_recovery_artifact_binding(
    const AuthenticatedRecoveryArtifact& artifact);
bool validate_recovery_artifact(
    const AuthenticatedRecoveryRequest& request,
    const AuthenticatedRecoveryArtifact& artifact);

class AuthenticatedAuditRecoveryEngine {
public:
    virtual ~AuthenticatedAuditRecoveryEngine() = default;
    virtual AuthenticatedRecoveryArtifact Recover(
        const AuthenticatedRecoveryRequest& request,
        int rank,
        int world_size) const = 0;
};

class AuthenticatedAuditRecoveryBackend {
public:
    virtual ~AuthenticatedAuditRecoveryBackend() = default;
    virtual AuthenticatedRecoveryArtifact Recover(
        const AuthenticatedRecoveryRequest& request,
        int rank,
        int world_size) const = 0;
};

class BackendAuthenticatedAuditRecoveryEngine final
    : public AuthenticatedAuditRecoveryEngine {
public:
    explicit BackendAuthenticatedAuditRecoveryEngine(
        const AuthenticatedAuditRecoveryBackend& backend)
        : backend_(backend) {}
    AuthenticatedRecoveryArtifact Recover(
        const AuthenticatedRecoveryRequest& request,
        int rank,
        int world_size) const override;
private:
    const AuthenticatedAuditRecoveryBackend& backend_;
};

class FailClosedAuthenticatedAuditRecoveryEngine final
    : public AuthenticatedAuditRecoveryEngine {
public:
    AuthenticatedRecoveryArtifact Recover(
        const AuthenticatedRecoveryRequest& request,
        int rank,
        int world_size) const override;
};

} // namespace pvia
