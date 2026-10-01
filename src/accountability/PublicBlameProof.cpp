#include "PublicBlameProof.hpp"
#include "PublicTransferEvidence.hpp"

#include <cstring>

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

bool is_public_transfer_relation(RelationKind relation) {
    return relation == RelationKind::MESSAGE_BINDING ||
           relation == RelationKind::RECEIVE_CONSUME;
}

} // namespace

std::vector<u64> encode_public_blame_statement(
    const PublicBlameStatement& statement) {
    std::vector<u64> words = {
        statement.sid,
        statement.accused.owner,
        statement.accused.object_id,
        static_cast<u64>(statement.label.phase),
        statement.label.round,
        statement.label.owner,
        static_cast<u64>(statement.label.obligation),
        statement.label.object_id,
        statement.checkpoint,
        static_cast<u64>(statement.relation),
        static_cast<u64>(statement.kernel),
        static_cast<u64>(statement.evidence_kind)
    };
    append_digest_words(statement.expected, words);
    append_digest_words(statement.actual, words);
    append_digest_words(statement.residual_commitment, words);
    append_digest_words(statement.operation_statement_binding, words);
    append_digest_words(statement.dispute_binding, words);
    append_digest_words(statement.audit_evidence_binding, words);
    append_digest_words(statement.predecessor_root, words);
    append_digest_words(statement.checkpoint_root, words);
    return words;
}

Digest compute_public_blame_statement_binding(
    const PublicBlameStatement& statement) {
    return hash_words(encode_public_blame_statement(statement));
}

PublicBlameStatement make_public_blame_statement(
    const Violation& violation,
    const RecoverableAuditShare& audit,
    const AuthenticatedRecoveryArtifact& recovery) {
    PublicBlameStatement statement;
    if (!violation.valid || !audit.valid ||
        audit.evidence_kind != AuditEvidenceKind::PRIVATE_RECOVERY ||
        is_public_transfer_relation(violation.relation) ||
        audit.witness_digest != compute_recovery_artifact_binding(recovery) ||
        audit.predecessor_root != recovery.predecessor_root ||
        audit.checkpoint_root != recovery.checkpoint_root)
        return statement;
    statement.sid = violation.label.sid;
    statement.accused = ref_from_label(violation.label);
    statement.label = violation.label;
    statement.checkpoint = violation.checkpoint;
    statement.relation = violation.relation;
    statement.kernel = violation.kernel;
    statement.evidence_kind = AuditEvidenceKind::PRIVATE_RECOVERY;
    statement.expected = violation.expected;
    statement.actual = violation.actual;
    statement.residual_commitment = violation.residual_commitment;
    statement.operation_statement_binding = violation.operation_statement_binding;
    statement.dispute_binding = violation.dispute_binding;
    statement.audit_evidence_binding =
        compute_recovery_artifact_binding(recovery);
    statement.predecessor_root = audit.predecessor_root;
    statement.checkpoint_root = audit.checkpoint_root;
    statement.statement_binding =
        compute_public_blame_statement_binding(statement);
    return statement;
}

PublicBlameStatement make_public_blame_statement(
    const Violation& violation,
    const RecoverableAuditShare& audit,
    const PublicTransferEvidence& evidence) {
    PublicBlameStatement statement;
    if (!violation.valid || !audit.valid || !evidence.available ||
        !evidence.cryptographically_authenticated ||
        audit.evidence_kind != AuditEvidenceKind::PUBLIC_TRANSFER ||
        !is_public_transfer_relation(violation.relation) ||
        violation.kernel != AuditRelationKernel::UNKNOWN ||
        evidence.accused != ref_from_label(violation.label) ||
        evidence.label.sid != violation.label.sid ||
        evidence.label.phase != violation.label.phase ||
        evidence.label.round != violation.label.round ||
        evidence.label.owner != violation.label.owner ||
        evidence.label.obligation != violation.label.obligation ||
        evidence.label.object_id != violation.label.object_id ||
        evidence.checkpoint != violation.checkpoint ||
        evidence.relation != violation.relation ||
        evidence.expected != violation.expected ||
        evidence.actual != violation.actual ||
        evidence.residual_commitment != violation.residual_commitment ||
        evidence.operation_statement_binding != violation.operation_statement_binding ||
        evidence.dispute_binding != violation.dispute_binding ||
        audit.predecessor_root != Digest{} ||
        audit.checkpoint_root != evidence.checkpoint_root ||
        audit.witness_digest != evidence.evidence_binding ||
        !validate_public_transfer_evidence_claim(evidence))
        return statement;
    statement.sid = violation.label.sid;
    statement.accused = ref_from_label(violation.label);
    statement.label = violation.label;
    statement.checkpoint = violation.checkpoint;
    statement.relation = violation.relation;
    statement.kernel = violation.kernel;
    statement.evidence_kind = AuditEvidenceKind::PUBLIC_TRANSFER;
    statement.expected = violation.expected;
    statement.actual = violation.actual;
    statement.residual_commitment = violation.residual_commitment;
    statement.operation_statement_binding = violation.operation_statement_binding;
    statement.dispute_binding = violation.dispute_binding;
    statement.audit_evidence_binding = evidence.evidence_binding;
    statement.predecessor_root = audit.predecessor_root;
    statement.checkpoint_root = audit.checkpoint_root;
    statement.statement_binding =
        compute_public_blame_statement_binding(statement);
    return statement;
}

PublicBlameStatement make_public_blame_statement(
    const BlameCertificate& certificate) {
    PublicBlameStatement statement;
    if (!certificate.valid) return statement;
    statement.sid = certificate.sid;
    statement.accused = OperationRef{
        certificate.accused, certificate.label.object_id};
    statement.label = certificate.label;
    statement.checkpoint = certificate.checkpoint;
    statement.relation = certificate.relation;
    statement.kernel = certificate.kernel;
    statement.evidence_kind = certificate.evidence_kind;
    statement.expected = certificate.expected;
    statement.actual = certificate.actual;
    statement.residual_commitment = certificate.residual_commitment;
    statement.operation_statement_binding = certificate.operation_statement_binding;
    statement.dispute_binding = certificate.dispute_binding;
    statement.audit_evidence_binding = certificate.audit_witness_digest;
    statement.predecessor_root = certificate.predecessor_root;
    statement.checkpoint_root = certificate.checkpoint_root;
    statement.statement_binding =
        compute_public_blame_statement_binding(statement);
    return statement;
}

Digest compute_public_blame_proof_commitment(
    const PublicBlameProofArtifact& artifact) {
    std::vector<u64> words = {
        artifact.available ? 1ULL : 0ULL,
        artifact.cryptographically_authenticated ? 1ULL : 0ULL,
        artifact.proof_system_id,
        static_cast<u64>(artifact.proof_words.size())
    };
    append_digest_words(artifact.statement_binding, words);
    append_digest_words(artifact.transcript_binding, words);
    words.insert(words.end(), artifact.proof_words.begin(),
                 artifact.proof_words.end());
    return hash_words(words);
}

bool validate_public_blame_proof_artifact(
    const PublicBlameStatement& statement,
    const PublicBlameProofArtifact& artifact) {
    if (!artifact.available || !artifact.cryptographically_authenticated ||
        artifact.proof_system_id == 0)
        return false;
    if (statement.statement_binding == Digest{} ||
        statement.statement_binding !=
            compute_public_blame_statement_binding(statement))
        return false;
    if (artifact.statement_binding != statement.statement_binding ||
        artifact.transcript_binding == Digest{} || artifact.proof_words.empty())
        return false;
    if (statement.sid == 0 || statement.label.sid != statement.sid ||
        statement.accused != ref_from_label(statement.label) ||
        statement.checkpoint == 0 || statement.relation == RelationKind::UNKNOWN ||
        statement.evidence_kind == AuditEvidenceKind::UNKNOWN)
        return false;
    if (statement.kernel != AuditRelationKernel::UNKNOWN &&
        relation_for_kernel(statement.kernel) != statement.relation)
        return false;
    if (statement.kernel == AuditRelationKernel::UNKNOWN &&
        statement.relation == RelationKind::PRIVATE_DERIVATION)
        return false;
    if (statement.evidence_kind == AuditEvidenceKind::PUBLIC_TRANSFER) {
        if (!is_public_transfer_relation(statement.relation) ||
            statement.kernel != AuditRelationKernel::UNKNOWN ||
            statement.predecessor_root != Digest{})
            return false;
    } else if (statement.evidence_kind == AuditEvidenceKind::PRIVATE_RECOVERY) {
        if (is_public_transfer_relation(statement.relation))
            return false;
    } else {
        return false;
    }
    if (statement.operation_statement_binding == Digest{} ||
        statement.dispute_binding == Digest{} ||
        statement.audit_evidence_binding == Digest{} ||
        statement.checkpoint_root == Digest{})
        return false;
    return artifact.proof_commitment ==
           compute_public_blame_proof_commitment(artifact);
}

PublicBlameProofArtifact BackendPublicBlameProofEngine::Prove(
    const PublicBlameStatement& statement,
    const AuthenticatedRecoveryArtifact& recovery) const {
    PublicBlameProofArtifact artifact;
    if (statement.evidence_kind != AuditEvidenceKind::PRIVATE_RECOVERY ||
        statement.statement_binding == Digest{} ||
        statement.statement_binding != compute_public_blame_statement_binding(statement) ||
        !recovery.available || !recovery.cryptographically_authenticated ||
        statement.audit_evidence_binding != compute_recovery_artifact_binding(recovery))
        return artifact;
    const std::vector<u64> public_inputs = encode_public_blame_statement(statement);
    const ExternalPublicBlameProof external = backend_.Prove(public_inputs, recovery);
    if (!external.available || !external.cryptographically_authenticated ||
        external.proof_system_id == 0 || external.transcript_binding == Digest{} ||
        external.proof_words.empty() || !backend_.Verify(public_inputs, external))
        return artifact;
    artifact.available = true;
    artifact.cryptographically_authenticated = true;
    artifact.proof_system_id = external.proof_system_id;
    artifact.statement_binding = statement.statement_binding;
    artifact.transcript_binding = external.transcript_binding;
    artifact.proof_words = external.proof_words;
    artifact.proof_commitment = compute_public_blame_proof_commitment(artifact);
    return artifact;
}

bool BackendPublicBlameProofEngine::Verify(
    const PublicBlameStatement& statement,
    const PublicBlameProofArtifact& artifact) const {
    if (statement.evidence_kind != AuditEvidenceKind::PRIVATE_RECOVERY ||
        !validate_public_blame_proof_artifact(statement, artifact))
        return false;
    ExternalPublicBlameProof external;
    external.available = artifact.available;
    external.cryptographically_authenticated = artifact.cryptographically_authenticated;
    external.proof_system_id = artifact.proof_system_id;
    external.transcript_binding = artifact.transcript_binding;
    external.proof_words = artifact.proof_words;
    return backend_.Verify(encode_public_blame_statement(statement), external);
}

PublicBlameProofArtifact FailClosedPublicBlameProofEngine::Prove(
    const PublicBlameStatement& statement,
    const AuthenticatedRecoveryArtifact&) const {
    PublicBlameProofArtifact artifact;
    artifact.available = false;
    artifact.cryptographically_authenticated = false;
    artifact.statement_binding = statement.statement_binding;
    return artifact;
}

bool FailClosedPublicBlameProofEngine::Verify(
    const PublicBlameStatement&,
    const PublicBlameProofArtifact&) const {
    return false;
}

} // namespace pvia
