#include "MpiResidualActivationScopeSynchronizer.hpp"
#include "CollectiveResidualEngine.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <vector>

namespace pvia {
namespace {

constexpr u64 ACTIVATION_SCOPE_SYNC_DOMAIN =
    0x5056524153594e43ULL; // PVRASYNC
constexpr u64 ACTIVATION_SCOPE_PREFLIGHT_KIND =
    0x5056524153505246ULL; // PVRASPRF
constexpr u64 ACTIVATION_SCOPE_META_KIND =
    0x50565241534d4554ULL; // PVRASMET
constexpr u64 ACTIVATION_SCOPE_DESC_KIND =
    0x5056524153444553ULL; // PVRASDES
constexpr u64 ACTIVATION_SCOPE_BIND_DOMAIN =
    0x505652415342494eULL; // PVRASBIN
constexpr u64 ACTIVATION_SCOPE_PREFLIGHT_BIND_DOMAIN =
    0x505652415350424eULL; // PVRASPBN
constexpr size_t ACTIVATION_SCOPE_META_WORDS = 9;
constexpr size_t MAX_LOCAL_PRIVATE_OPERATIONS = 1U << 20;

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

Digest read_digest(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}

bool ref_less(const OperationRef& lhs, const OperationRef& rhs) {
    return lhs.owner != rhs.owner ? lhs.owner < rhs.owner
                                  : lhs.object_id < rhs.object_id;
}

bool build_private_obligation_mask(
    const std::vector<Obligation>& obligations, u64* mask) {
    if (!mask) return false;
    u64 out = 0;
    for (Obligation obligation : obligations) {
        const u64 raw = static_cast<u64>(obligation);
        if (raw == 0 || raw >= 64 ||
            classify_audit_obligation(obligation) !=
                AuditScopeLane::PRIVATE_RESIDUAL)
            return false;
        out |= 1ULL << raw;
    }
    *mask = out;
    return true;
}

bool decode_private_obligation_mask(
    u64 mask, std::vector<Obligation>* obligations) {
    if (!obligations) return false;
    obligations->clear();
    for (u64 raw = 1; raw <= static_cast<u64>(Obligation::OPEN); ++raw) {
        if ((mask & (1ULL << raw)) == 0) continue;
        const Obligation obligation =
            static_cast<Obligation>(static_cast<uint32_t>(raw));
        if (classify_audit_obligation(obligation) !=
            AuditScopeLane::PRIVATE_RESIDUAL)
            return false;
        obligations->push_back(obligation);
    }
    const u64 known_bits =
        (static_cast<u64>(Obligation::OPEN) >= 63)
            ? std::numeric_limits<u64>::max()
            : ((1ULL << (static_cast<u64>(Obligation::OPEN) + 1)) - 1ULL);
    return (mask & ~known_bits) == 0;
}

bool valid_local_fragment(
    const ObligationSet& fragment, int rank, int world_size) {
    if (rank < 0 || world_size <= 0 || rank >= world_size ||
        fragment.session_id == 0 || fragment.phase == Phase::UNKNOWN ||
        fragment.checkpoint == 0 || fragment.checkpoint_root == Digest{} ||
        !fragment.exact_round || !fragment.transfer_operations.empty() ||
        fragment.operations != fragment.private_operations ||
        fragment.operations.size() > MAX_LOCAL_PRIVATE_OPERATIONS)
        return false;
    u64 obligation_mask = 0;
    if (!build_private_obligation_mask(fragment.obligations, &obligation_mask))
        return false;
    if (!fragment.operations.empty() && obligation_mask == 0) return false;

    std::vector<OperationRef> refs = fragment.operations;
    for (const OperationRef& ref : refs) {
        if (ref.owner != static_cast<uint32_t>(rank) || ref.object_id == 0)
            return false;
    }
    std::sort(refs.begin(), refs.end(), ref_less);
    return std::adjacent_find(refs.begin(), refs.end()) == refs.end();
}

AuthenticatedMpcMessageContext make_context(
    const ObligationSet& fragment, uint64_t sync_sequence, u64 kind) {
    AuthenticatedMpcMessageContext context;
    context.protocol_domain = ACTIVATION_SCOPE_SYNC_DOMAIN;
    context.sid = fragment.session_id;
    context.checkpoint = fragment.checkpoint;
    context.round = fragment.round;
    context.sequence = sync_sequence;
    context.message_kind = kind;
    return context;
}

} // namespace

ResidualActivationScopeSyncResult
MpiResidualActivationScopeSynchronizer::SynchronizeAuthenticated(
    const ObligationSet& local_fragment,
    const AuthenticatedMpcExchange& exchange,
    int rank, int world_size,
    uint64_t sync_sequence) {
    ResidualActivationScopeSyncResult result;
    if (sync_sequence == 0 ||
        !exchange.production_authenticated_ready() ||
        !valid_local_fragment(local_fragment, rank, world_size))
        return result;

    u64 local_obligation_mask = 0;
    if (!build_private_obligation_mask(
            local_fragment.obligations, &local_obligation_mask))
        return result;

    std::vector<u64> metadata = {
        static_cast<u64>(local_fragment.phase),
        local_fragment.generation,
        local_fragment.exact_round ? 1ULL : 0ULL};
    append_digest(local_fragment.checkpoint_root, &metadata);
    metadata.push_back(static_cast<u64>(local_fragment.operations.size()));
    metadata.push_back(local_obligation_mask);
    if (metadata.size() != ACTIVATION_SCOPE_META_WORDS) return result;

    std::vector<u64> gathered_metadata;
    if (!exchange.AllGatherWords(
            make_context(local_fragment, sync_sequence,
                         ACTIVATION_SCOPE_META_KIND),
            metadata, &gathered_metadata,
            &result.metadata_transcript_binding) ||
        result.metadata_transcript_binding == Digest{} ||
        gathered_metadata.size() !=
            static_cast<size_t>(world_size) * ACTIVATION_SCOPE_META_WORDS)
        return result;
    std::vector<size_t> counts(static_cast<size_t>(world_size), 0);
    size_t max_count = 0;
    u64 obligation_union_mask = 0;
    for (int sender = 0; sender < world_size; ++sender) {
        const size_t off =
            static_cast<size_t>(sender) * ACTIVATION_SCOPE_META_WORDS;
        if (gathered_metadata[off] != static_cast<u64>(local_fragment.phase) ||
            gathered_metadata[off + 1] != local_fragment.generation ||
            gathered_metadata[off + 2] != 1ULL ||
            read_digest(gathered_metadata, off + 3) !=
                local_fragment.checkpoint_root)
            return result;
        const u64 raw_count = gathered_metadata[off + 7];
        const u64 peer_mask = gathered_metadata[off + 8];
        if (raw_count > MAX_LOCAL_PRIVATE_OPERATIONS) return result;
        std::vector<Obligation> peer_obligations;
        if (!decode_private_obligation_mask(peer_mask, &peer_obligations) ||
            (raw_count != 0 && peer_mask == 0))
            return result;
        counts[static_cast<size_t>(sender)] =
            static_cast<size_t>(raw_count);
        max_count = std::max(max_count, static_cast<size_t>(raw_count));
        obligation_union_mask |= peer_mask;
    }

    if (max_count >
        (static_cast<size_t>(std::numeric_limits<int>::max()) - 1U) / 2U)
        return result;
    const size_t descriptor_words = 1U + 2U * max_count;
    std::vector<u64> descriptor(descriptor_words, 0);
    descriptor[0] = static_cast<u64>(local_fragment.operations.size());
    std::vector<OperationRef> local_refs = local_fragment.operations;
    std::sort(local_refs.begin(), local_refs.end(), ref_less);
    for (size_t i = 0; i < local_refs.size(); ++i) {
        descriptor[1 + 2 * i] = local_refs[i].owner;
        descriptor[1 + 2 * i + 1] = local_refs[i].object_id;
    }

    std::vector<u64> gathered_descriptors;
    if (!exchange.AllGatherWords(
            make_context(local_fragment, sync_sequence,
                         ACTIVATION_SCOPE_DESC_KIND),
            descriptor, &gathered_descriptors,
            &result.descriptor_transcript_binding) ||
        result.descriptor_transcript_binding == Digest{} ||
        gathered_descriptors.size() !=
            static_cast<size_t>(world_size) * descriptor_words)
        return result;

    std::vector<OperationRef> canonical_refs;
    for (int sender = 0; sender < world_size; ++sender) {
        const size_t off = static_cast<size_t>(sender) * descriptor_words;
        const size_t count = counts[static_cast<size_t>(sender)];
        if (gathered_descriptors[off] != static_cast<u64>(count))
            return result;
        for (size_t i = 0; i < max_count; ++i) {
            const u64 raw_owner = gathered_descriptors[off + 1 + 2 * i];
            const u64 object_id = gathered_descriptors[off + 1 + 2 * i + 1];
            if (i < count) {
                if (raw_owner != static_cast<u64>(sender) || object_id == 0 ||
                    raw_owner > std::numeric_limits<uint32_t>::max())
                    return result;
                canonical_refs.push_back(OperationRef{
                    static_cast<uint32_t>(raw_owner), object_id});
            } else if (raw_owner != 0 || object_id != 0) {
                return result;
            }
        }
    }

    std::sort(canonical_refs.begin(), canonical_refs.end(), ref_less);
    if (std::adjacent_find(canonical_refs.begin(), canonical_refs.end()) !=
        canonical_refs.end())
        return result;

    ObligationSet canonical = local_fragment;
    canonical.operations = canonical_refs;
    canonical.private_operations = canonical_refs;
    canonical.transfer_operations.clear();
    if (!decode_private_obligation_mask(
            obligation_union_mask, &canonical.obligations))
        return result;
    const Digest scope_binding = compute_collective_scope_binding(canonical);
    const Digest transport_binding = exchange.ProductionCapabilityBinding();
    if (scope_binding == Digest{} || transport_binding == Digest{}) return result;

    std::vector<u64> binding_words = {
        ACTIVATION_SCOPE_BIND_DOMAIN,
        canonical.session_id,
        canonical.checkpoint,
        sync_sequence,
        static_cast<u64>(canonical.operations.size())};
    append_digest(result.metadata_transcript_binding, &binding_words);
    append_digest(result.descriptor_transcript_binding, &binding_words);
    append_digest(scope_binding, &binding_words);
    append_digest(transport_binding, &binding_words);
    result.binding = hash_words(binding_words);
    if (result.binding == Digest{}) return ResidualActivationScopeSyncResult{};

    result.available = true;
    result.scope = std::move(canonical);
    return result;
}


ResidualActivationScopeSyncResult
MpiResidualActivationScopeSynchronizer::BuildAndSynchronizeAuthenticated(
    const AuditCheckpointView& checkpoint,
    const PrivateAuditMaterialStore& materials,
    uint64_t expected_session_id,
    const AuthenticatedMpcExchange& exchange,
    int rank, int world_size,
    uint64_t sync_sequence) {
    ResidualActivationScopeSyncResult unavailable;
    if (expected_session_id == 0 || sync_sequence == 0 ||
        rank < 0 || world_size <= 0 || rank >= world_size ||
        !exchange.production_authenticated_ready())
        return unavailable;

    ObligationSet local_fragment;
    const bool local_ready = build_local_private_residual_activation_scope(
        checkpoint, materials, static_cast<uint32_t>(rank),
        expected_session_id, &local_fragment);

    AuthenticatedMpcMessageContext preflight_context;
    preflight_context.protocol_domain = ACTIVATION_SCOPE_SYNC_DOMAIN;
    preflight_context.sid = expected_session_id;
    preflight_context.checkpoint = checkpoint.id;
    preflight_context.round = checkpoint.round;
    preflight_context.sequence = sync_sequence;
    preflight_context.message_kind = ACTIVATION_SCOPE_PREFLIGHT_KIND;

    bool all_ready = false;
    Digest preflight_binding{};
    if (!exchange.AllTrue(
            preflight_context, local_ready, &all_ready,
            &preflight_binding) ||
        !all_ready || preflight_binding == Digest{})
        return unavailable;

    ResidualActivationScopeSyncResult result = SynchronizeAuthenticated(
        local_fragment, exchange, rank, world_size, sync_sequence);
    if (!result.available || result.binding == Digest{}) return unavailable;

    const Digest core_binding = result.binding;
    std::vector<u64> words = {
        ACTIVATION_SCOPE_PREFLIGHT_BIND_DOMAIN,
        expected_session_id,
        checkpoint.id,
        sync_sequence};
    append_digest(preflight_binding, &words);
    append_digest(core_binding, &words);
    result.binding = hash_words(words);
    if (result.binding == Digest{}) return unavailable;
    result.preflight_transcript_binding = preflight_binding;
    return result;
}

} // namespace pvia
