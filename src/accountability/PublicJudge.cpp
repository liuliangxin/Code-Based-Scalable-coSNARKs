#include "PublicJudge.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

namespace pvia {
namespace {

void append_digest_words(const Digest& digest, std::vector<u64>& words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + i * 8, 8);
        words.push_back(word);
    }
}

bool evidence_ref_less(const OperationEvidence& lhs,
                       const OperationEvidence& rhs) {
    if (lhs.ref.owner != rhs.ref.owner) return lhs.ref.owner < rhs.ref.owner;
    return lhs.ref.object_id < rhs.ref.object_id;
}

Digest predecessor_root_from_evidence(
    const std::vector<OperationEvidence>& evidence) {
    std::vector<u64> words;
    for (const auto& item : evidence) {
        words.push_back(item.ref.owner);
        words.push_back(item.ref.object_id);
        append_digest_words(item.actual, words);
        append_digest_words(item.predecessor_root, words);
    }
    return hash_words(words);
}

Digest checkpoint_root_from_evidence(const BlameCertificate& cert) {
    std::vector<OperationEvidence> evidence = cert.checkpoint_evidence;
    std::sort(evidence.begin(), evidence.end(), evidence_ref_less);
    std::vector<u64> words = {
        cert.checkpoint, static_cast<u64>(cert.label.phase), cert.label.round };
    for (const auto& item : evidence) {
        words.push_back(item.ref.owner);
        words.push_back(item.ref.object_id);
        words.push_back(static_cast<u64>(item.obligation));
        words.push_back(static_cast<u64>(item.relation));
        words.push_back(static_cast<u64>(item.kernel));
        words.push_back(item.source_checkpoint_hint);
        words.push_back(item.predecessor_count);
        words.push_back(item.state_dependency_count);
        words.push_back(item.public_aux_count);
        append_digest_words(item.expected, words);
        append_digest_words(item.actual, words);
        append_digest_words(item.predecessor_root, words);
        append_digest_words(item.state_dependency_root, words);
        append_digest_words(item.public_aux_root, words);
        append_digest_words(item.relation_statement, words);
    }
    return hash_words(words);
}

bool valid_checkpoint_relation_evidence(
    const BlameCertificate& cert, const OperationEvidence& item) {
    const RelationKind expected_relation = relation_for_obligation(item.obligation);
    if (item.relation != expected_relation) return false;
    if (item.relation == RelationKind::PRIVATE_DERIVATION &&
        item.kernel == AuditRelationKernel::UNKNOWN) return false;
    if (item.kernel != AuditRelationKernel::UNKNOWN &&
        relation_for_kernel(item.kernel) != item.relation) return false;
    if (!item.public_aux_evidence_complete) return false;
    if (item.public_aux_count != item.public_aux_evidence.size()) return false;
    if (item.public_aux_root != compute_public_aux_root(item.public_aux_evidence))
        return false;
    if (!item.state_dependency_evidence_complete) return false;
    if (item.state_dependency_count != item.state_dependency_evidence.size())
        return false;
    if (item.state_dependency_root !=
        compute_state_dependency_root(item.state_dependency_evidence))
        return false;

    Label label;
    label.sid = cert.sid;
    label.phase = cert.label.phase;
    label.round = cert.label.round;
    label.owner = item.ref.owner;
    label.obligation = item.obligation;
    label.object_id = item.ref.object_id;
    return item.relation_statement == compute_relation_statement(
        label, item.relation, item.kernel, item.expected, item.predecessor_root,
        item.predecessor_count, item.state_dependency_root,
        item.state_dependency_count, item.public_aux_root, item.public_aux_count);
}

const OperationEvidence* accused_operation(const BlameCertificate& cert) {
    for (const auto& item : cert.checkpoint_evidence) {
        if (item.ref.owner == cert.label.owner &&
            item.ref.object_id == cert.label.object_id)
            return &item;
    }
    return nullptr;
}

} // namespace

Digest PublicJudge::compute_debug_proof_digest(
    const BlameCertificate& cert) {
    std::vector<u64> words = {
        cert.sid,
        cert.accused,
        static_cast<u64>(cert.label.phase),
        cert.label.round,
        cert.label.owner,
        static_cast<u64>(cert.label.obligation),
        cert.label.object_id,
        cert.checkpoint,
        static_cast<u64>(cert.relation),
        static_cast<u64>(cert.kernel),
        cert.predecessor_evidence_complete ? 1ULL : 0ULL,
        static_cast<u64>(cert.predecessor_evidence.size()),
        static_cast<u64>(cert.checkpoint_evidence.size())
    };
    append_digest_words(cert.expected, words);
    append_digest_words(cert.actual, words);
    append_digest_words(cert.residual_commitment, words);
    append_digest_words(cert.operation_statement_binding, words);
    append_digest_words(cert.dispute_binding, words);
    append_digest_words(cert.predecessor_root, words);
    append_digest_words(cert.checkpoint_root, words);
    append_digest_words(cert.audit_witness_digest, words);
    append_digest_words(cert.transcript_digest, words);
    append_digest_words(cert.blame_statement_binding, words);
    words.push_back(cert.public_proof_system_id);
    append_digest_words(cert.public_proof_commitment, words);
    append_digest_words(cert.public_proof_transcript_binding, words);
    words.push_back(static_cast<u64>(cert.public_proof_words.size()));
    words.insert(words.end(), cert.public_proof_words.begin(),
                 cert.public_proof_words.end());
    return hash_words(words);
}

bool PublicJudge::VerifyDebug(const BlameCertificate& cert,
                              uint64_t expected_session_id) {
    if (!cert.valid || !cert.debug_only) return false;
    if (cert.blame_statement_binding != Digest{} ||
        cert.public_proof_system_id != 0 ||
        cert.public_proof_commitment != Digest{} ||
        cert.public_proof_transcript_binding != Digest{} ||
        !cert.public_proof_words.empty())
        return false;
    if (cert.sid != expected_session_id) return false;
    if (cert.label.sid != cert.sid) return false;
    if (cert.accused != cert.label.owner) return false;
    if (cert.expected == cert.actual) return false;
    if (cert.relation == RelationKind::UNKNOWN) return false;
    if (cert.kernel == AuditRelationKernel::UNKNOWN &&
        cert.relation == RelationKind::PRIVATE_DERIVATION) return false;
    if (cert.kernel != AuditRelationKernel::UNKNOWN &&
        relation_for_kernel(cert.kernel) != cert.relation) return false;
    if (cert.checkpoint_root == Digest{} ||
        cert.operation_statement_binding == Digest{}) return false;
    if (cert.residual_commitment != compute_residual_commitment(
            cert.label, cert.relation, cert.kernel, cert.expected, cert.actual))
        return false;

    if (!cert.predecessor_evidence_complete) return false;
    if (cert.predecessor_root !=
        predecessor_root_from_evidence(cert.predecessor_evidence))
        return false;
    if (cert.checkpoint_evidence.empty()) return false;
    for (const auto& evidence : cert.checkpoint_evidence) {
        if (!valid_checkpoint_relation_evidence(cert, evidence)) return false;
    }
    if (cert.checkpoint_root != checkpoint_root_from_evidence(cert))
        return false;

    const OperationEvidence* accused = accused_operation(cert);
    if (!accused) return false;
    if (accused->predecessor_root != cert.predecessor_root) return false;
    if (accused->predecessor_count != cert.predecessor_evidence.size())
        return false;
    if (accused->relation_statement != cert.operation_statement_binding)
        return false;
    if (cert.relation == RelationKind::MESSAGE_BINDING) {
        if (cert.kernel != AuditRelationKernel::UNKNOWN) return false;
        if (accused->actual != cert.expected) return false;
    } else {
        if (accused->kernel != cert.kernel) return false;
        if (accused->obligation != cert.label.obligation) return false;
        if (accused->relation != cert.relation) return false;
        if (accused->expected != cert.expected || accused->actual != cert.actual)
            return false;
    }

    if (cert.checkpoint == 0) return false;
    const uint32_t checkpoint_phase =
        static_cast<uint32_t>((cert.checkpoint >> 56) & 0xffULL);
    const uint32_t checkpoint_round =
        static_cast<uint32_t>((cert.checkpoint >> 24) & 0xffffffffULL);
    if (checkpoint_phase != static_cast<uint32_t>(cert.label.phase)) return false;
    if (checkpoint_round != cert.label.round) return false;

    return cert.proof_digest == compute_debug_proof_digest(cert);
}

} // namespace pvia
