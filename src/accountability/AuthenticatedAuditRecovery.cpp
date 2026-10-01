#include "AuthenticatedAuditRecovery.hpp"

#include <cstring>
#include <vector>

namespace pvia {
namespace {

void append_digest_words(const Digest& digest, std::vector<u64>& words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words.push_back(word);
    }
}

OperationRef ref_from_label(const Label& label) {
    return OperationRef{label.owner, label.object_id};
}

} // namespace
Digest compute_recovery_request_binding(
    const AuthenticatedRecoveryRequest& request) {
    std::vector<u64> words = {
        request.label.sid,
        static_cast<u64>(request.label.phase),
        request.label.round,
        request.label.owner,
        static_cast<u64>(request.label.obligation),
        request.label.object_id,
        request.checkpoint,
        static_cast<u64>(request.relation),
        static_cast<u64>(request.kernel)
    };
    append_digest_words(request.expected, words);
    append_digest_words(request.actual, words);
    append_digest_words(request.residual_commitment, words);
    append_digest_words(request.operation_statement_binding, words);
    append_digest_words(request.dispute_binding, words);
    append_digest_words(request.checkpoint_root, words);
    return hash_words(words);
}
AuthenticatedRecoveryRequest make_recovery_request(
    const Violation& violation,
    const AuditCheckpointView& checkpoint) {
    AuthenticatedRecoveryRequest request;
    if (!violation.valid || violation.operation_statement_binding == Digest{} ||
        !checkpoint.sealed || checkpoint.root == Digest{} ||
        checkpoint.id != violation.checkpoint)
        return request;
    request.label = violation.label;
    request.checkpoint = violation.checkpoint;
    request.relation = violation.relation;
    request.kernel = violation.kernel;
    request.expected = violation.expected;
    request.actual = violation.actual;
    request.residual_commitment = violation.residual_commitment;
    request.operation_statement_binding = violation.operation_statement_binding;
    request.dispute_binding = violation.dispute_binding;
    request.checkpoint_root = checkpoint.root;
    request.request_binding = compute_recovery_request_binding(request);
    return request;
}
Digest compute_recovery_artifact_binding(
    const AuthenticatedRecoveryArtifact& artifact) {
    std::vector<u64> words = {
        artifact.available ? 1ULL : 0ULL,
        artifact.cryptographically_authenticated ? 1ULL : 0ULL,
        artifact.accused.owner,
        artifact.accused.object_id,
        artifact.checkpoint,
        static_cast<u64>(artifact.relation),
        static_cast<u64>(artifact.kernel)
    };
    append_digest_words(artifact.request_binding, words);
    append_digest_words(artifact.operation_statement_binding, words);
    append_digest_words(artifact.dispute_binding, words);
    append_digest_words(artifact.predecessor_root, words);
    append_digest_words(artifact.checkpoint_root, words);
    append_digest_words(artifact.recovered_audit_commitment, words);
    append_digest_words(artifact.recovery_transcript_binding, words);
    append_digest_words(artifact.authentication_proof_commitment, words);
    return hash_words(words);
}
bool validate_recovery_artifact(
    const AuthenticatedRecoveryRequest& request,
    const AuthenticatedRecoveryArtifact& artifact) {
    if (!artifact.available || !artifact.cryptographically_authenticated)
        return false;
    if (request.request_binding == Digest{} ||
        request.operation_statement_binding == Digest{} ||
        request.request_binding != compute_recovery_request_binding(request))
        return false;
    if (artifact.accused != ref_from_label(request.label) ||
        artifact.checkpoint != request.checkpoint ||
        artifact.relation != request.relation ||
        artifact.kernel != request.kernel)
        return false;
    if (artifact.request_binding != request.request_binding ||
        artifact.operation_statement_binding != request.operation_statement_binding ||
        artifact.dispute_binding != request.dispute_binding ||
        artifact.checkpoint_root != request.checkpoint_root)
        return false;
    if (artifact.recovered_audit_commitment == Digest{} ||
        artifact.recovery_transcript_binding == Digest{} ||
        artifact.authentication_proof_commitment == Digest{})
        return false;
    return compute_recovery_artifact_binding(artifact) != Digest{};
}
AuthenticatedRecoveryArtifact
BackendAuthenticatedAuditRecoveryEngine::Recover(
    const AuthenticatedRecoveryRequest& request,
    int rank,
    int world_size) const {
    AuthenticatedRecoveryArtifact unavailable;
    unavailable.accused = ref_from_label(request.label);
    unavailable.checkpoint = request.checkpoint;
    unavailable.relation = request.relation;
    unavailable.kernel = request.kernel;
    unavailable.request_binding = request.request_binding;
    unavailable.operation_statement_binding =
        request.operation_statement_binding;
    unavailable.dispute_binding = request.dispute_binding;
    unavailable.checkpoint_root = request.checkpoint_root;

    if (request.request_binding == Digest{} ||
        request.request_binding != compute_recovery_request_binding(request))
        return unavailable;
    const AuthenticatedRecoveryArtifact artifact =
        backend_.Recover(request, rank, world_size);
    if (!validate_recovery_artifact(request, artifact))
        return unavailable;
    return artifact;
}

AuthenticatedRecoveryArtifact
FailClosedAuthenticatedAuditRecoveryEngine::Recover(
    const AuthenticatedRecoveryRequest& request,
    int,
    int) const {
    AuthenticatedRecoveryArtifact artifact;
    artifact.available = false;
    artifact.cryptographically_authenticated = false;
    artifact.accused = ref_from_label(request.label);
    artifact.checkpoint = request.checkpoint;
    artifact.relation = request.relation;
    artifact.kernel = request.kernel;
    artifact.request_binding = request.request_binding;
    artifact.operation_statement_binding = request.operation_statement_binding;
    artifact.dispute_binding = request.dispute_binding;
    artifact.checkpoint_root = request.checkpoint_root;
    return artifact;
}

} // namespace pvia
