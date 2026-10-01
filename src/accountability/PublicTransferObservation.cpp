#include "PublicTransferObservation.hpp"
#include "TransferAuthentication.hpp"

#include <algorithm>
#include <cstring>

namespace pvia {
namespace {

Digest digest_from_words(const u64* words) {
    Digest digest;
    std::memcpy(digest.bytes.data(), words, digest.bytes.size());
    return digest;
}

void append_digest_words(const Digest& digest, std::vector<u64>& words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words.push_back(word);
    }
}

bool same_ref(const OperationRef& lhs, const OperationRef& rhs) {
    return lhs.owner == rhs.owner && lhs.object_id == rhs.object_id;
}

bool contains_ref(const std::vector<OperationRef>& refs,
                  const OperationRef& ref) {
    return refs.empty() ||
        std::find(refs.begin(), refs.end(), ref) != refs.end();
}

} // namespace

std::vector<u64> encode_public_transfer_observation(
    const PublicTransferObservation& observation) {
    std::vector<u64> words = {
        observation.valid ? 1ULL : 0ULL,
        observation.ref.owner,
        observation.ref.object_id,
        observation.source_label.sid,
        static_cast<u64>(observation.source_label.phase),
        observation.source_label.round,
        observation.source_label.owner,
        static_cast<u64>(observation.source_label.obligation),
        observation.source_label.object_id,
        observation.transfer_label.sid,
        static_cast<u64>(observation.transfer_label.phase),
        observation.transfer_label.round,
        observation.transfer_label.owner,
        static_cast<u64>(observation.transfer_label.obligation),
        observation.transfer_label.object_id,
        observation.checkpoint,
        observation.observer_rank,
        observation.remote_observation ? 1ULL : 0ULL
    };
    words.push_back(observation.predecessor_count);
    append_digest_words(observation.predecessor_root, words);
    words.push_back(observation.state_dependency_count);
    append_digest_words(observation.state_dependency_root, words);
    words.push_back(observation.public_aux_count);
    append_digest_words(observation.public_aux_root, words);
    append_digest_words(observation.registered_digest, words);
    append_digest_words(observation.payload_digest, words);
    append_digest_words(observation.operation_statement_binding, words);
    append_digest_words(observation.metadata_binding, words);
    words.insert(words.end(), observation.authenticated_metadata.begin(),
                 observation.authenticated_metadata.end());
    return words;
}

bool decode_public_transfer_observation_unchecked(
    const std::vector<u64>& words,
    PublicTransferObservation* observation) {
    if (!observation || words.size() != PUBLIC_TRANSFER_OBSERVATION_WORDS)
        return false;
    PublicTransferObservation out;
    out.valid = words[0] != 0;
    out.ref.owner = static_cast<uint32_t>(words[1]);
    out.ref.object_id = words[2];
    out.source_label.sid = words[3];
    out.source_label.phase = static_cast<Phase>(static_cast<uint32_t>(words[4]));
    out.source_label.round = static_cast<uint32_t>(words[5]);
    out.source_label.owner = static_cast<uint32_t>(words[6]);
    out.source_label.obligation = static_cast<Obligation>(static_cast<uint32_t>(words[7]));
    out.source_label.object_id = words[8];
    out.transfer_label.sid = words[9];
    out.transfer_label.phase = static_cast<Phase>(static_cast<uint32_t>(words[10]));
    out.transfer_label.round = static_cast<uint32_t>(words[11]);
    out.transfer_label.owner = static_cast<uint32_t>(words[12]);
    out.transfer_label.obligation = static_cast<Obligation>(static_cast<uint32_t>(words[13]));
    out.transfer_label.object_id = words[14];
    out.checkpoint = words[15];
    out.observer_rank = static_cast<uint32_t>(words[16]);
    out.remote_observation = words[17] != 0;
    out.predecessor_count = static_cast<uint32_t>(words[18]);
    out.state_dependency_count = static_cast<uint32_t>(words[23]);
    out.public_aux_count = static_cast<uint32_t>(words[28]);
    auto load_digest = [&](size_t offset, Digest* digest) {
        for (size_t i = 0; i < 4; ++i)
            std::memcpy(digest->bytes.data() + 8 * i, &words[offset + i], 8);
    };
    load_digest(19, &out.predecessor_root);
    load_digest(24, &out.state_dependency_root);
    load_digest(29, &out.public_aux_root);
    load_digest(33, &out.registered_digest);
    load_digest(37, &out.payload_digest);
    load_digest(41, &out.operation_statement_binding);
    load_digest(45, &out.metadata_binding);
    std::copy(words.begin() + PUBLIC_TRANSFER_OBSERVATION_BASE_WORDS,
              words.end(), out.authenticated_metadata.begin());
    *observation = out;
    return true;
}

namespace {
bool validate_public_transfer_observation_structure(
    const PublicTransferObservation& observation) {
    if (!observation.valid) return false;
    if (observation.ref.owner != observation.source_label.owner ||
        observation.ref.object_id != observation.source_label.object_id)
        return false;
    if (observation.source_label.sid == 0) return false;
    if (observation.transfer_label.sid != observation.source_label.sid ||
        observation.transfer_label.phase != observation.source_label.phase ||
        observation.transfer_label.round != observation.source_label.round ||
        observation.transfer_label.owner != observation.source_label.owner ||
        observation.transfer_label.object_id != observation.source_label.object_id ||
        observation.transfer_label.obligation != Obligation::SEND)
        return false;
    const auto& meta = observation.authenticated_metadata;
    if (meta[1] != observation.source_label.sid ||
        meta[2] != static_cast<u64>(observation.source_label.phase) ||
        meta[3] != observation.source_label.round ||
        meta[4] != observation.source_label.owner ||
        meta[5] != static_cast<u64>(observation.source_label.obligation) ||
        meta[6] != observation.source_label.object_id)
        return false;
    if (observation.checkpoint == 0 ||
        meta[META_CHECKPOINT_INDEX] != observation.checkpoint ||
        observation.predecessor_root == Digest{} ||
        observation.state_dependency_root == Digest{} ||
        observation.public_aux_root == Digest{} ||
        observation.operation_statement_binding == Digest{} ||
        observation.metadata_binding == Digest{})
        return false;
    if (digest_from_words(&meta[8]) != observation.registered_digest ||
        digest_from_words(&meta[META_AUTH_WIRE_DIGEST_OFFSET]) !=
            observation.payload_digest ||
        digest_from_words(&meta[META_PREDECESSOR_ROOT_OFFSET]) !=
            observation.predecessor_root ||
        static_cast<uint32_t>(meta[META_PREDECESSOR_COUNT_INDEX]) !=
            observation.predecessor_count ||
        digest_from_words(&meta[META_STATE_DEP_ROOT_OFFSET]) !=
            observation.state_dependency_root ||
        static_cast<uint32_t>(meta[META_STATE_DEP_COUNT_INDEX]) !=
            observation.state_dependency_count ||
        digest_from_words(&meta[META_PUBLIC_AUX_ROOT_OFFSET]) !=
            observation.public_aux_root ||
        static_cast<uint32_t>(meta[META_PUBLIC_AUX_COUNT_INDEX]) !=
            observation.public_aux_count)
        return false;
    const Digest expected_metadata_binding = hash_words(
        std::vector<u64>(meta.begin(), meta.end()));
    if (observation.metadata_binding != expected_metadata_binding) return false;
    const Digest expected_statement = compute_relation_statement(
        observation.transfer_label, RelationKind::MESSAGE_BINDING,
        AuditRelationKernel::UNKNOWN, observation.registered_digest,
        observation.predecessor_root, observation.predecessor_count,
        observation.state_dependency_root, observation.state_dependency_count,
        observation.public_aux_root, observation.public_aux_count);
    if (observation.operation_statement_binding != expected_statement)
        return false;
    return compute_public_transfer_observation_binding(observation) != Digest{};
}
} // namespace

bool validate_public_transfer_observation(
    const PublicTransferObservation& observation) {
    if (!validate_public_transfer_observation_structure(observation))
        return false;
    const auto& auth = Ed25519TransferAuthenticator::instance();
    return auth.ready() && auth.Verify(
        observation.authenticated_metadata,
        static_cast<int>(observation.source_label.owner));
}

bool validate_public_transfer_observation_with_public_key(
    const PublicTransferObservation& observation,
    const std::array<uint8_t, 32>& public_key) {
    return validate_public_transfer_observation_structure(observation) &&
        verify_ed25519_transfer_meta_with_public_key(
            observation.authenticated_metadata, public_key,
            static_cast<int>(observation.source_label.owner));
}

bool decode_public_transfer_observation(
    const std::vector<u64>& words,
    PublicTransferObservation* observation) {
    PublicTransferObservation out;
    if (!decode_public_transfer_observation_unchecked(words, &out) ||
        !validate_public_transfer_observation(out))
        return false;
    *observation = out;
    return true;
}

Digest compute_public_transfer_observation_binding(
    const PublicTransferObservation& observation) {
    return hash_words(encode_public_transfer_observation(observation));
}

void PublicTransferObservationStore::Put(
    const PublicTransferObservation& observation) {
    if (!validate_public_transfer_observation(observation)) return;
    observations_.push_back(observation);
}

bool PublicTransferObservationStore::Has(const OperationRef& ref) const {
    return std::any_of(observations_.begin(), observations_.end(),
        [&](const PublicTransferObservation& observation) {
            return same_ref(observation.ref, ref);
        });
}

std::vector<PublicTransferObservation>
PublicTransferObservationStore::Select(const ObligationSet& scope) const {
    std::vector<PublicTransferObservation> out;
    for (const auto& observation : observations_) {
        if (!observation.valid) continue;
        if (scope.session_id != 0 &&
            observation.transfer_label.sid != scope.session_id)
            continue;
        if (scope.phase != Phase::UNKNOWN &&
            observation.transfer_label.phase != scope.phase)
            continue;
        if (scope.exact_round &&
            observation.transfer_label.round != scope.round)
            continue;
        if (scope.checkpoint != 0 &&
            observation.checkpoint != scope.checkpoint)
            continue;
        const Obligation transfer_obligation =
            observation.transfer_label.obligation;
        if (transfer_obligation != Obligation::SEND &&
            transfer_obligation != Obligation::RECEIVE &&
            transfer_obligation != Obligation::CONSUME)
            continue;
        if (!scope.obligations.empty() &&
            std::find(scope.obligations.begin(), scope.obligations.end(),
                      transfer_obligation) == scope.obligations.end())
            continue;
        if (!contains_ref(scope.operations, observation.ref)) continue;
        out.push_back(observation);
    }
    return out;
}

} // namespace pvia
