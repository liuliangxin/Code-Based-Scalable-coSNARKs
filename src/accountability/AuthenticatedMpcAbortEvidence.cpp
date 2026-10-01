#include "AuthenticatedMpcAbortEvidence.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

namespace pvia {
namespace {

constexpr u64 MPC_SIGNATURE_DOMAIN = AUTHENTICATED_MPC_SIGNATURE_DOMAIN;
constexpr u64 MPC_EQUIVOCATION_DOMAIN = 0x50564d5045515632ULL; // PVMPEQV2
constexpr u64 MPC_OBSERVATION_DOMAIN = 0x50564d504f425631ULL; // PVMPOBV1
constexpr u64 MPC_OBSERVATION_SET_DOMAIN = 0x50564d504f425332ULL; // PVMPOBS2
constexpr u64 MPC_ABORT_CAP_DOMAIN = 0x50564d5041424341ULL; // PVMPABCA
constexpr u64 MPC_ABORT_IMPL_DOMAIN = 0x50564d504142494dULL; // PVMPABIM
constexpr u64 MPC_ABORT_PROTOCOL_ID = 0x4d50434142525632ULL; // MPCABRV2

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

void append_signature(
    const std::array<uint8_t, 64>& signature,
    std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < signature.size() / sizeof(u64); ++i) {
        u64 word = 0;
        std::memcpy(&word, signature.data() + i * sizeof(u64), sizeof(u64));
        words->push_back(word);
    }
}

bool same_context(
    const AuthenticatedMpcMessageContext& a,
    const AuthenticatedMpcMessageContext& b) {
    return a.protocol_domain == b.protocol_domain && a.sid == b.sid &&
        a.checkpoint == b.checkpoint && a.round == b.round &&
        a.sequence == b.sequence && a.message_kind == b.message_kind;
}

} // namespace

Digest compute_authenticated_mpc_abort_evidence_capability_binding(
    const AuthenticatedMpcAbortEvidenceCapabilities& c) {
    std::vector<u64> words = {
        MPC_ABORT_CAP_DOMAIN, c.available ? 1ULL : 0ULL,
        c.signed_equivocation ? 1ULL : 0ULL,
        c.public_registry_verification ? 1ULL : 0ULL,
        c.external_registry_anchor_required ? 1ULL : 0ULL,
        c.payload_binding_signatures ? 1ULL : 0ULL,
        c.payload_contents_redacted ? 1ULL : 0ULL,
        c.protocol_id};
    append_digest(c.transport_capability_binding, &words);
    append_digest(c.implementation_binding, &words);
    return hash_words(words);
}

bool validate_authenticated_mpc_abort_evidence_capabilities(
    const AuthenticatedMpcAbortEvidenceCapabilities& c) {
    return c.available && c.protocol_id != 0 &&
        c.transport_capability_binding != Digest{} &&
        c.implementation_binding != Digest{} && c.capability_binding != Digest{} &&
        c.capability_binding ==
            compute_authenticated_mpc_abort_evidence_capability_binding(c);
}

bool production_ready_authenticated_mpc_abort_evidence_capabilities(
    const AuthenticatedMpcAbortEvidenceCapabilities& c) {
    return validate_authenticated_mpc_abort_evidence_capabilities(c) &&
        c.signed_equivocation && c.public_registry_verification &&
        c.external_registry_anchor_required &&
        c.payload_binding_signatures && c.payload_contents_redacted;
}

AuthenticatedMpcAbortEvidenceCapabilities
make_signed_equivocation_abort_evidence_capabilities(
    const Digest& transport_capability_binding) {
    AuthenticatedMpcAbortEvidenceCapabilities c;
    if (transport_capability_binding == Digest{}) return c;
    c.available = true;
    c.signed_equivocation = true;
    c.public_registry_verification = true;
    c.external_registry_anchor_required = true;
    c.payload_binding_signatures = true;
    c.payload_contents_redacted = true;
    c.protocol_id = MPC_ABORT_PROTOCOL_ID;
    c.transport_capability_binding = transport_capability_binding;
    c.implementation_binding = hash_words({MPC_ABORT_IMPL_DOMAIN, 2ULL});
    c.capability_binding =
        compute_authenticated_mpc_abort_evidence_capability_binding(c);
    return c;
}

Digest compute_authenticated_mpc_signed_envelope_observation_binding(
    const AuthenticatedMpcSignedEnvelopeObservation& observation) {
    if (!observation.available ||
        !validate_authenticated_mpc_message_context(observation.context) ||
        observation.payload_word_count == 0 ||
        observation.payload_binding == Digest{} ||
        observation.registry_commitment == Digest{})
        return Digest{};
    std::vector<u64> words = {
        MPC_OBSERVATION_DOMAIN,
        static_cast<u64>(observation.sender),
        static_cast<u64>(observation.receiver),
        observation.payload_word_count};
    append_digest(
        compute_authenticated_mpc_context_binding(observation.context), &words);
    append_digest(observation.payload_binding, &words);
    append_digest(observation.registry_commitment, &words);
    append_signature(observation.signature, &words);
    return hash_words(words);
}

bool verify_authenticated_mpc_signed_envelope_observation(
    const AuthenticatedMpcSignedEnvelopeObservation& observation,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& expected_registry_anchor) {
    if (public_keys.empty() || expected_registry_anchor == Digest{} ||
        observation.registry_commitment != expected_registry_anchor ||
        observation.sender >= public_keys.size() ||
        (observation.receiver != AUTHENTICATED_MPC_BROADCAST_RECEIVER &&
         observation.receiver >= public_keys.size()) ||
        observation.observation_binding == Digest{} ||
        observation.observation_binding !=
            compute_authenticated_mpc_signed_envelope_observation_binding(
                observation))
        return false;
    const std::vector<u64> message = build_authenticated_mpc_signed_message(
        observation.context, observation.sender, observation.receiver,
        public_keys.size(), observation.payload_word_count,
        observation.payload_binding);
    return !message.empty() && verify_ed25519_words_with_public_registry(
        MPC_SIGNATURE_DOMAIN, message, observation.signature,
        observation.sender, public_keys, expected_registry_anchor);
}

Digest compute_authenticated_mpc_equivocation_evidence_binding(
    const AuthenticatedMpcEquivocationEvidence& evidence) {
    if (!evidence.available ||
        evidence.kind != AuthenticatedMpcAbortEvidenceKind::SIGNED_EQUIVOCATION ||
        !validate_authenticated_mpc_message_context(evidence.context) ||
        evidence.public_keys.empty() ||
        evidence.sender >= evidence.public_keys.size() ||
        (evidence.receiver != AUTHENTICATED_MPC_BROADCAST_RECEIVER &&
         evidence.receiver >= evidence.public_keys.size()) ||
        evidence.first_payload_word_count == 0 ||
        evidence.second_payload_word_count == 0 ||
        evidence.first_payload_binding == Digest{} ||
        evidence.second_payload_binding == Digest{} ||
        (evidence.first_payload_word_count == evidence.second_payload_word_count &&
         evidence.first_payload_binding == evidence.second_payload_binding) ||
        evidence.registry_commitment == Digest{})
        return Digest{};
    std::vector<u64> words = {
        MPC_EQUIVOCATION_DOMAIN,
        static_cast<u64>(evidence.kind),
        static_cast<u64>(evidence.sender),
        static_cast<u64>(evidence.receiver),
        static_cast<u64>(evidence.public_keys.size()),
        evidence.first_payload_word_count,
        evidence.second_payload_word_count};
    append_digest(
        compute_authenticated_mpc_context_binding(evidence.context), &words);
    append_digest(evidence.registry_commitment, &words);
    append_digest(evidence.first_payload_binding, &words);
    append_signature(evidence.first_signature, &words);
    append_digest(evidence.second_payload_binding, &words);
    append_signature(evidence.second_signature, &words);
    return hash_words(words);
}

bool combine_authenticated_mpc_equivocation_observations(
    const AuthenticatedMpcSignedEnvelopeObservation& first,
    const AuthenticatedMpcSignedEnvelopeObservation& second,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& expected_registry_anchor,
    AuthenticatedMpcEquivocationEvidence* evidence) {
    if (!evidence ||
        !verify_authenticated_mpc_signed_envelope_observation(
            first, public_keys, expected_registry_anchor) ||
        !verify_authenticated_mpc_signed_envelope_observation(
            second, public_keys, expected_registry_anchor) ||
        !same_context(first.context, second.context) ||
        first.sender != second.sender || first.receiver != second.receiver ||
        first.registry_commitment != second.registry_commitment ||
        (first.payload_word_count == second.payload_word_count &&
         first.payload_binding == second.payload_binding))
        return false;

    const auto binding_less = [](const Digest& lhs, const Digest& rhs) {
        return std::lexicographical_compare(
            lhs.bytes.begin(), lhs.bytes.end(),
            rhs.bytes.begin(), rhs.bytes.end());
    };
    const AuthenticatedMpcSignedEnvelopeObservation* lhs = &first;
    const AuthenticatedMpcSignedEnvelopeObservation* rhs = &second;
    if (binding_less(second.observation_binding, first.observation_binding)) {
        lhs = &second;
        rhs = &first;
    }

    AuthenticatedMpcEquivocationEvidence candidate;
    candidate.available = true;
    candidate.kind = AuthenticatedMpcAbortEvidenceKind::SIGNED_EQUIVOCATION;
    candidate.context = lhs->context;
    candidate.sender = lhs->sender;
    candidate.receiver = lhs->receiver;
    candidate.first_payload_word_count = lhs->payload_word_count;
    candidate.first_payload_binding = lhs->payload_binding;
    candidate.first_signature = lhs->signature;
    candidate.second_payload_word_count = rhs->payload_word_count;
    candidate.second_payload_binding = rhs->payload_binding;
    candidate.second_signature = rhs->signature;
    candidate.public_keys = public_keys;
    candidate.registry_commitment = expected_registry_anchor;
    candidate.evidence_binding =
        compute_authenticated_mpc_equivocation_evidence_binding(candidate);
    if (candidate.evidence_binding == Digest{} ||
        !verify_authenticated_mpc_equivocation_evidence(
            candidate, expected_registry_anchor))
        return false;
    *evidence = std::move(candidate);
    return true;
}

Digest compute_authenticated_mpc_observation_set_binding(
    const std::vector<AuthenticatedMpcSignedEnvelopeObservation>& observations) {
    if (observations.empty()) return Digest{};
    std::vector<Digest> bindings;
    bindings.reserve(observations.size());
    for (const auto& observation : observations) {
        const Digest binding =
            compute_authenticated_mpc_signed_envelope_observation_binding(
                observation);
        if (binding == Digest{} || binding != observation.observation_binding)
            return Digest{};
        bindings.push_back(binding);
    }
    const auto digest_less = [](const Digest& lhs, const Digest& rhs) {
        return std::lexicographical_compare(
            lhs.bytes.begin(), lhs.bytes.end(),
            rhs.bytes.begin(), rhs.bytes.end());
    };
    std::sort(bindings.begin(), bindings.end(), digest_less);
    bindings.erase(std::unique(bindings.begin(), bindings.end()), bindings.end());
    std::vector<u64> words = {
        MPC_OBSERVATION_SET_DOMAIN, static_cast<u64>(bindings.size())};
    for (const Digest& binding : bindings) append_digest(binding, &words);
    return hash_words(words);
}

AuthenticatedMpcObservationReconciliation
reconcile_authenticated_mpc_observations(
    const std::vector<AuthenticatedMpcSignedEnvelopeObservation>& observations,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& expected_registry_anchor) {
    AuthenticatedMpcObservationReconciliation result;
    result.input_count = observations.size();
    if (observations.empty() || public_keys.empty() ||
        expected_registry_anchor == Digest{})
        return result;
    std::vector<AuthenticatedMpcSignedEnvelopeObservation> canonical;
    canonical.reserve(observations.size());
    for (const auto& observation : observations) {
        if (!verify_authenticated_mpc_signed_envelope_observation(
                observation, public_keys, expected_registry_anchor)) {
            ++result.rejected_count;
            continue;
        }
        canonical.push_back(observation);
    }
    if (canonical.empty()) return result;
    const size_t verified_count = canonical.size();
    const auto observation_less = [](const auto& lhs, const auto& rhs) {
        return std::lexicographical_compare(
            lhs.observation_binding.bytes.begin(),
            lhs.observation_binding.bytes.end(),
            rhs.observation_binding.bytes.begin(),
            rhs.observation_binding.bytes.end());
    };
    std::sort(canonical.begin(), canonical.end(), observation_less);
    canonical.erase(std::unique(canonical.begin(), canonical.end(),
        [](const auto& lhs, const auto& rhs) {
            return lhs.observation_binding == rhs.observation_binding;
        }), canonical.end());
    result.duplicate_count = verified_count - canonical.size();
    result.observation_set_binding =
        compute_authenticated_mpc_observation_set_binding(canonical);
    if (result.observation_set_binding == Digest{}) return result;
    result.valid = true;
    result.accepted_count = canonical.size();
    result.observation_count = result.accepted_count;
    for (size_t i = 0; i < canonical.size(); ++i) {
        for (size_t j = i + 1; j < canonical.size(); ++j) {
            if (!same_context(canonical[i].context, canonical[j].context) ||
                canonical[i].sender != canonical[j].sender ||
                canonical[i].receiver != canonical[j].receiver ||
                (canonical[i].payload_word_count ==
                     canonical[j].payload_word_count &&
                 canonical[i].payload_binding == canonical[j].payload_binding))
                continue;
            AuthenticatedMpcEquivocationEvidence evidence;
            if (!combine_authenticated_mpc_equivocation_observations(
                    canonical[i], canonical[j], public_keys,
                    expected_registry_anchor, &evidence))
                return AuthenticatedMpcObservationReconciliation{};
            result.equivocation_found = true;
            result.evidence = std::move(evidence);
            return result;
        }
    }
    return result;
}

bool verify_authenticated_mpc_equivocation_evidence(
    const AuthenticatedMpcEquivocationEvidence& evidence,
    const Digest& expected_registry_anchor) {
    if (expected_registry_anchor == Digest{} ||
        evidence.registry_commitment != expected_registry_anchor ||
        evidence.evidence_binding == Digest{} ||
        evidence.evidence_binding !=
            compute_authenticated_mpc_equivocation_evidence_binding(evidence))
        return false;
    const Digest registry =
        compute_ed25519_registry_commitment(evidence.public_keys);
    if (registry == Digest{} || registry != evidence.registry_commitment)
        return false;
    const std::vector<u64> first_message =
        build_authenticated_mpc_signed_message(
            evidence.context, evidence.sender, evidence.receiver,
            evidence.public_keys.size(), evidence.first_payload_word_count,
            evidence.first_payload_binding);
    const std::vector<u64> second_message =
        build_authenticated_mpc_signed_message(
            evidence.context, evidence.sender, evidence.receiver,
            evidence.public_keys.size(), evidence.second_payload_word_count,
            evidence.second_payload_binding);
    if (first_message.empty() || second_message.empty()) return false;
    return verify_ed25519_words_with_public_registry(
               MPC_SIGNATURE_DOMAIN, first_message,
               evidence.first_signature, evidence.sender,
               evidence.public_keys, evidence.registry_commitment) &&
           verify_ed25519_words_with_public_registry(
               MPC_SIGNATURE_DOMAIN, second_message,
               evidence.second_signature, evidence.sender,
               evidence.public_keys, evidence.registry_commitment);
}

} // namespace pvia

namespace pvia {
bool run_authenticated_mpc_equivocation_evidence_selftest(
    int rank, int world_size,
    AuthenticatedMpcEquivocationEvidence* verified_evidence) {
    auto& auth = Ed25519TransferAuthenticator::instance();
    if (!auth.ready() || auth.rank() != rank ||
        auth.world_size() != world_size || world_size <= 0 ||
        auth.RegistryCommitment() == Digest{})
        return false;
    AuthenticatedMpcMessageContext context;
    context.protocol_domain = 0x45515653454c4654ULL; // EQVSELFT
    context.sid = 0x4551565349443031ULL; // EQVSID01
    context.checkpoint = 0x455156434b505431ULL; // EQVCKPT1
    context.round = 7;
    context.sequence = 1;
    context.message_kind = 0x4551564d53473031ULL; // EQVMSG01
    const std::vector<u64> first_payload = {
        static_cast<u64>(rank), 11ULL, 22ULL};
    const std::vector<u64> second_payload = {
        static_cast<u64>(rank), 11ULL, 23ULL};
    const Digest first_payload_binding =
        compute_authenticated_mpc_payload_binding(first_payload);
    const Digest second_payload_binding =
        compute_authenticated_mpc_payload_binding(second_payload);
    const std::vector<u64> first_message =
        build_authenticated_mpc_signed_message(
            context, static_cast<uint32_t>(rank),
            AUTHENTICATED_MPC_BROADCAST_RECEIVER,
            static_cast<size_t>(world_size),
            static_cast<uint64_t>(first_payload.size()),
            first_payload_binding);
    const std::vector<u64> second_message =
        build_authenticated_mpc_signed_message(
            context, static_cast<uint32_t>(rank),
            AUTHENTICATED_MPC_BROADCAST_RECEIVER,
            static_cast<size_t>(world_size),
            static_cast<uint64_t>(second_payload.size()),
            second_payload_binding);
    std::array<uint8_t, 64> first_signature{};
    std::array<uint8_t, 64> second_signature{};
    if (first_message.empty() || second_message.empty() ||
        !auth.SignWords(MPC_SIGNATURE_DOMAIN, first_message, &first_signature) ||
        !auth.SignWords(MPC_SIGNATURE_DOMAIN, second_message, &second_signature))
        return false;
    AuthenticatedMpcEquivocationEvidence evidence;
    evidence.available = true;
    evidence.kind = AuthenticatedMpcAbortEvidenceKind::SIGNED_EQUIVOCATION;
    evidence.context = context;
    evidence.sender = static_cast<uint32_t>(rank);
    evidence.receiver = AUTHENTICATED_MPC_BROADCAST_RECEIVER;
    evidence.first_payload_word_count =
        static_cast<uint64_t>(first_payload.size());
    evidence.first_payload_binding = first_payload_binding;
    evidence.first_signature = first_signature;
    evidence.second_payload_word_count =
        static_cast<uint64_t>(second_payload.size());
    evidence.second_payload_binding = second_payload_binding;
    evidence.second_signature = second_signature;
    evidence.public_keys = auth.PublicKeys();
    evidence.registry_commitment = auth.RegistryCommitment();
    evidence.evidence_binding =
        compute_authenticated_mpc_equivocation_evidence_binding(evidence);
    if (evidence.evidence_binding == Digest{} ||
        !verify_authenticated_mpc_equivocation_evidence(
            evidence, auth.RegistryCommitment()))
        return false;

    AuthenticatedMpcSignedEnvelopeObservation first_observation;
    first_observation.available = true;
    first_observation.context = context;
    first_observation.sender = static_cast<uint32_t>(rank);
    first_observation.receiver = AUTHENTICATED_MPC_BROADCAST_RECEIVER;
    first_observation.payload_word_count = first_payload.size();
    first_observation.payload_binding = first_payload_binding;
    first_observation.signature = first_signature;
    first_observation.registry_commitment = auth.RegistryCommitment();
    first_observation.observation_binding =
        compute_authenticated_mpc_signed_envelope_observation_binding(
            first_observation);
    AuthenticatedMpcSignedEnvelopeObservation second_observation;
    second_observation.available = true;
    second_observation.context = context;
    second_observation.sender = static_cast<uint32_t>(rank);
    second_observation.receiver = AUTHENTICATED_MPC_BROADCAST_RECEIVER;
    second_observation.payload_word_count = second_payload.size();
    second_observation.payload_binding = second_payload_binding;
    second_observation.signature = second_signature;
    second_observation.registry_commitment = auth.RegistryCommitment();
    second_observation.observation_binding =
        compute_authenticated_mpc_signed_envelope_observation_binding(
            second_observation);
    AuthenticatedMpcEquivocationEvidence combined_forward;
    AuthenticatedMpcEquivocationEvidence combined_reverse;
    if (!verify_authenticated_mpc_signed_envelope_observation(
            first_observation, auth.PublicKeys(), auth.RegistryCommitment()) ||
        !verify_authenticated_mpc_signed_envelope_observation(
            second_observation, auth.PublicKeys(), auth.RegistryCommitment()) ||
        !combine_authenticated_mpc_equivocation_observations(
            first_observation, second_observation,
            auth.PublicKeys(), auth.RegistryCommitment(), &combined_forward) ||
        !combine_authenticated_mpc_equivocation_observations(
            second_observation, first_observation,
            auth.PublicKeys(), auth.RegistryCommitment(), &combined_reverse) ||
        combined_forward.evidence_binding != combined_reverse.evidence_binding)
        return false;
    const std::vector<AuthenticatedMpcSignedEnvelopeObservation> forward_set = {
        first_observation, second_observation, first_observation};
    const std::vector<AuthenticatedMpcSignedEnvelopeObservation> reverse_set = {
        second_observation, first_observation};
    const auto reconciled_forward = reconcile_authenticated_mpc_observations(
        forward_set, auth.PublicKeys(), auth.RegistryCommitment());
    const auto reconciled_reverse = reconcile_authenticated_mpc_observations(
        reverse_set, auth.PublicKeys(), auth.RegistryCommitment());
    const auto clean_single = reconcile_authenticated_mpc_observations(
        {first_observation}, auth.PublicKeys(), auth.RegistryCommitment());
    if (!reconciled_forward.valid || !reconciled_forward.equivocation_found ||
        reconciled_forward.input_count != 3 ||
        reconciled_forward.accepted_count != 2 ||
        reconciled_forward.rejected_count != 0 ||
        reconciled_forward.duplicate_count != 1 ||
        reconciled_forward.observation_count != 2 ||
        !reconciled_reverse.valid || !reconciled_reverse.equivocation_found ||
        reconciled_forward.observation_set_binding == Digest{} ||
        reconciled_forward.observation_set_binding !=
            reconciled_reverse.observation_set_binding ||
        reconciled_forward.evidence.evidence_binding !=
            reconciled_reverse.evidence.evidence_binding ||
        !clean_single.valid || clean_single.equivocation_found ||
        clean_single.input_count != 1 || clean_single.accepted_count != 1 ||
        clean_single.rejected_count != 0 || clean_single.duplicate_count != 0 ||
        clean_single.observation_count != 1)
        return false;
    AuthenticatedMpcSignedEnvelopeObservation tampered_observation =
        second_observation;
    tampered_observation.payload_binding.bytes[0] ^= 1U;
    const auto byzantine_filtered = reconcile_authenticated_mpc_observations(
        {first_observation, tampered_observation, second_observation},
        auth.PublicKeys(), auth.RegistryCommitment());
    if (!byzantine_filtered.valid ||
        !byzantine_filtered.equivocation_found ||
        byzantine_filtered.input_count != 3 ||
        byzantine_filtered.accepted_count != 2 ||
        byzantine_filtered.rejected_count != 1 ||
        byzantine_filtered.duplicate_count != 0 ||
        byzantine_filtered.input_count !=
            byzantine_filtered.accepted_count +
            byzantine_filtered.rejected_count +
            byzantine_filtered.duplicate_count ||
        byzantine_filtered.observation_count != 2 ||
        byzantine_filtered.evidence.evidence_binding !=
            combined_forward.evidence_binding)
        return false;
    if (verify_authenticated_mpc_signed_envelope_observation(
            tampered_observation, auth.PublicKeys(), auth.RegistryCommitment()) ||
        combine_authenticated_mpc_equivocation_observations(
            first_observation, first_observation,
            auth.PublicKeys(), auth.RegistryCommitment(), &combined_reverse))
        return false;

    AuthenticatedMpcEquivocationEvidence tampered = evidence;
    tampered.second_payload_binding.bytes[0] ^= 1U;
    if (verify_authenticated_mpc_equivocation_evidence(
            tampered, auth.RegistryCommitment()))
        return false;
    tampered = evidence;
    tampered.evidence_binding.bytes[0] ^= 1U;
    if (verify_authenticated_mpc_equivocation_evidence(
            tampered, auth.RegistryCommitment()))
        return false;
    Digest wrong_anchor = auth.RegistryCommitment();
    wrong_anchor.bytes[0] ^= 1U;
    if (verify_authenticated_mpc_equivocation_evidence(
            evidence, wrong_anchor))
        return false;
    if (verified_evidence) *verified_evidence = evidence;
    return true;
}
} // namespace pvia
