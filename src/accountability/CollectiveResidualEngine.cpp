#include "CollectiveResidualEngine.hpp"

#include <algorithm>
#include <cstring>

namespace pvia {
namespace {

constexpr u64 RESIDUAL_SECURITY_LINK_MARKER = 0x5056525345434c4bULL; // PVRSECLK

void append_digest_words(const Digest& digest, std::vector<u64>& words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words.push_back(word);
    }
}

bool operation_less(const OperationRef& lhs, const OperationRef& rhs) {
    if (lhs.owner != rhs.owner) return lhs.owner < rhs.owner;
    return lhs.object_id < rhs.object_id;
}

bool contains_operation(const std::vector<OperationRef>& operations,
                        const OperationRef& ref) {
    if (operations.empty()) return true;
    return std::find(operations.begin(), operations.end(), ref) != operations.end();
}

} // namespace

Digest compute_collective_scope_binding(const ObligationSet& scope) {
    std::vector<Obligation> obligations = scope.obligations;
    std::sort(obligations.begin(), obligations.end(),
        [](Obligation lhs, Obligation rhs) {
            return static_cast<uint32_t>(lhs) < static_cast<uint32_t>(rhs);
        });
    std::vector<OperationRef> operations = scope.operations;
    std::vector<OperationRef> private_operations = scope.private_operations;
    std::vector<OperationRef> transfer_operations = scope.transfer_operations;
    std::sort(operations.begin(), operations.end(), operation_less);
    std::sort(private_operations.begin(), private_operations.end(), operation_less);
    std::sort(transfer_operations.begin(), transfer_operations.end(), operation_less);
    std::vector<u64> words = {
        scope.session_id,
        static_cast<u64>(scope.phase), scope.round, scope.generation,
        scope.exact_round ? 1ULL : 0ULL, scope.checkpoint,
        static_cast<u64>(obligations.size()),
        static_cast<u64>(operations.size()),
        static_cast<u64>(private_operations.size()),
        static_cast<u64>(transfer_operations.size())
    };
    for (Obligation obligation : obligations)
        words.push_back(static_cast<u64>(obligation));
    for (const auto& ref : operations) {
        words.push_back(ref.owner);
        words.push_back(ref.object_id);
    }
    for (const auto& ref : private_operations) {
        words.push_back(ref.owner);
        words.push_back(ref.object_id);
    }
    for (const auto& ref : transfer_operations) {
        words.push_back(ref.owner);
        words.push_back(ref.object_id);
    }
    append_digest_words(scope.checkpoint_root, words);
    return hash_words(words);
}

Digest compute_collective_descriptor_digest(
    const ObligationSet& scope,
    uint32_t local_owner,
    int world_size,
    size_t local_handle_count,
    const Digest& local_commitment_root) {
    std::vector<u64> words = {
        static_cast<u64>(local_owner),
        static_cast<u64>(world_size),
        static_cast<u64>(local_handle_count)
    };
    append_digest_words(compute_collective_scope_binding(scope), words);
    append_digest_words(local_commitment_root, words);
    return hash_words(words);
}

CollectiveBatchDescriptor make_collective_batch_descriptor(
    const ObligationSet& scope,
    const LocalResidualBatchView& local_view,
    int rank,
    int world_size) {
    CollectiveBatchDescriptor descriptor;
    descriptor.scope = scope;
    descriptor.local_owner = static_cast<uint32_t>(rank);
    descriptor.world_size = world_size;
    descriptor.local_handle_count = local_view.handles.size();
    descriptor.local_commitment_root = local_view.commitment_root;

    descriptor.descriptor_digest = compute_collective_descriptor_digest(
        scope, descriptor.local_owner, world_size,
        descriptor.local_handle_count, descriptor.local_commitment_root);
    return descriptor;
}

Digest compute_collective_batch_result_binding(
    const BatchCheckResult& result) {
    std::vector<u64> words = {
        result.available ? 1ULL : 0ULL,
        result.cryptographically_authenticated ? 1ULL : 0ULL,
        result.ok ? 1ULL : 0ULL,
        result.checkpoint,
        static_cast<u64>(result.checked_operations),
        static_cast<u64>(result.mismatches),
        static_cast<u64>(result.participant_count)
    };
    append_digest_words(result.scope_binding, words);
    append_digest_words(result.participant_commitment_root, words);
    append_digest_words(result.challenge_transcript_binding, words);
    append_digest_words(result.challenge, words);
    if (result.security_attestation_binding != Digest{}) {
        words.push_back(RESIDUAL_SECURITY_LINK_MARKER);
        append_digest_words(result.security_attestation_binding, words);
    }
    append_digest_words(result.aggregate_residual_commitment, words);
    return hash_words(words);
}

Digest compute_collective_dispute_binding(
    const CollectiveDisputeResult& result) {
    std::vector<u64> words = {
        result.available ? 1ULL : 0ULL,
        result.cryptographically_authenticated ? 1ULL : 0ULL,
        result.found ? 1ULL : 0ULL,
        result.accused.owner,
        result.accused.object_id,
        result.checkpoint,
        static_cast<u64>(result.relation),
        static_cast<u64>(result.kernel),
        result.label.sid,
        static_cast<u64>(result.label.phase),
        result.label.round,
        result.label.owner,
        static_cast<u64>(result.label.obligation),
        result.label.object_id
    };
    append_digest_words(result.expected, words);
    append_digest_words(result.actual, words);
    append_digest_words(result.residual_commitment, words);
    append_digest_words(result.operation_statement_binding, words);
    append_digest_words(result.batch_result_binding, words);
    append_digest_words(result.public_evidence_binding, words);
    if (result.security_attestation_binding != Digest{}) {
        words.push_back(RESIDUAL_SECURITY_LINK_MARKER);
        append_digest_words(result.security_attestation_binding, words);
    }
    append_digest_words(result.recursive_transcript_binding, words);
    append_digest_words(result.localization_commitment, words);
    return hash_words(words);
}

bool validate_collective_batch_result(
    const ObligationSet& scope,
    const BatchCheckResult& result,
    int world_size) {
    if (!result.available || !result.cryptographically_authenticated)
        return false;
    if (world_size <= 0) return false;
    if (result.checkpoint != scope.checkpoint) return false;
    if (result.participant_count != static_cast<size_t>(world_size)) return false;
    if (result.scope_binding != compute_collective_scope_binding(scope)) return false;
    if (result.participant_commitment_root == Digest{} ||
        result.challenge_transcript_binding == Digest{}) return false;
    if (!scope.operations.empty() &&
        result.checked_operations != scope.operations.size())
        return false;
    if (result.challenge == Digest{} ||
        result.aggregate_residual_commitment == Digest{})
        return false;
    if (result.ok && result.mismatches != 0) return false;
    if (!result.ok && result.mismatches == 0) return false;
    return true;
}
bool validate_collective_dispute_result(
    const ObligationSet& scope,
    const BatchCheckResult& batch,
    const CollectiveDisputeResult& result) {
    if (!batch.available || !batch.cryptographically_authenticated || batch.ok)
        return false;
    if (!result.available || !result.cryptographically_authenticated ||
        !result.found)
        return false;
    if (result.checkpoint != scope.checkpoint ||
        result.checkpoint != batch.checkpoint)
        return false;
    if (!contains_operation(scope.operations, result.accused)) return false;
    if (result.label.sid != scope.session_id ||
        result.label.owner != result.accused.owner ||
        result.label.object_id != result.accused.object_id ||
        result.label.phase != scope.phase)
        return false;
    if (scope.exact_round && result.label.round != scope.round) return false;
    if (result.relation == RelationKind::UNKNOWN ||
        relation_for_obligation(result.label.obligation) != result.relation)
        return false;
    if (result.kernel != AuditRelationKernel::UNKNOWN &&
        relation_for_kernel(result.kernel) != result.relation)
        return false;
    if (result.kernel == AuditRelationKernel::UNKNOWN &&
        result.relation == RelationKind::PRIVATE_DERIVATION)
        return false;
    if (result.expected == result.actual ||
        result.operation_statement_binding == Digest{})
        return false;
    if (result.residual_commitment != compute_residual_commitment(
            result.label, result.relation, result.kernel,
            result.expected, result.actual))
        return false;
    if (result.batch_result_binding !=
        compute_collective_batch_result_binding(batch))
        return false;
    if (result.public_evidence_binding != Digest{}) return false;
    if (result.security_attestation_binding !=
        batch.security_attestation_binding) return false;
    if (result.recursive_transcript_binding == Digest{}) return false;
    if (result.localization_commitment == Digest{}) return false;
    return true;
}

Violation materialize_collective_violation(
    const CollectiveDisputeResult& result) {
    Violation violation;
    if (!result.available || !result.cryptographically_authenticated ||
        !result.found || result.operation_statement_binding == Digest{})
        return violation;
    violation.valid = true;
    violation.label = result.label;
    violation.expected = result.expected;
    violation.actual = result.actual;
    violation.responsible_rank = result.accused.owner;
    violation.checkpoint = result.checkpoint;
    violation.relation = result.relation;
    violation.kernel = result.kernel;
    violation.residual_commitment = result.residual_commitment;
    violation.operation_statement_binding = result.operation_statement_binding;
    violation.dispute_binding = compute_collective_dispute_binding(result);
    violation.sequence = 0;
    violation.resolved = false;
    return violation;
}

BatchCheckResult FailClosedCollectiveResidualEngine::BatchCheck(
    const ObligationSet& scope,
    const LocalResidualBatchView&,
    int,
    int) const {
    BatchCheckResult result;
    result.available = false;
    result.cryptographically_authenticated = false;
    result.ok = false;
    result.checkpoint = scope.checkpoint;
    return result;
}

CollectiveDisputeResult FailClosedCollectiveResidualEngine::Dispute(
    const ObligationSet& scope,
    const BatchCheckResult&,
    const LocalResidualBatchView&,
    int,
    int) const {
    CollectiveDisputeResult result;
    result.available = false;
    result.cryptographically_authenticated = false;
    result.found = false;
    result.checkpoint = scope.checkpoint;
    return result;
}

} // namespace pvia
