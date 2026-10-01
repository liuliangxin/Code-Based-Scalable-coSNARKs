#include "MultiplicationConsistencySharingWitness.hpp"

#include "MultiplicationConsistencyProviderAbiC.h"
#include "ReferenceBivariateVss.hpp"
#include "ReferenceLinearSharingProvenance.hpp"

#include <cstring>
#include <limits>

namespace pvia {
namespace {

void append_digest(
    const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

Digest read_digest(
    const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    if (offset > words.size() || words.size() - offset < 4)
        return digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(
            digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}

bool derive_binding(
    MultiplicationConsistencySharingWitnessKind kind,
    const std::vector<u64>& payload_words,
    Digest* binding) {
    if (!binding || payload_words.empty()) return false;
    *binding = Digest{};
    switch (kind) {
        case MultiplicationConsistencySharingWitnessKind::VSS_LOCAL: {
            ReferenceVssLocalWitness witness;
            if (!decode_reference_vss_local_witness(
                    payload_words, &witness))
                return false;
            *binding = witness.transcript_binding;
            return *binding != Digest{};
        }
        case MultiplicationConsistencySharingWitnessKind::LINEAR_COMBINATION: {
            ReferenceLinearSharingProvenance provenance;
            if (!decode_reference_linear_sharing_provenance(
                    payload_words, &provenance))
                return false;
            *binding = provenance.binding;
            return *binding != Digest{};
        }
        case MultiplicationConsistencySharingWitnessKind::VSS_DEALER: {
            ReferenceVssDealerWitness witness;
            if (!decode_reference_vss_dealer_witness(
                    payload_words, &witness))
                return false;
            *binding = witness.transcript_binding;
            return *binding != Digest{};
        }
    }
    return false;
}

} // namespace

bool validate_multiplication_consistency_sharing_witness(
    const MultiplicationConsistencySharingWitnessEnvelope& witness) {
    if (witness.sharing_binding == Digest{} ||
        witness.payload_words.empty())
        return false;
    Digest derived{};
    return derive_binding(
               witness.kind, witness.payload_words, &derived) &&
        derived == witness.sharing_binding;
}

std::vector<u64> encode_multiplication_consistency_sharing_witness(
    const MultiplicationConsistencySharingWitnessEnvelope& witness) {
    if (!validate_multiplication_consistency_sharing_witness(witness))
        return {};
    std::vector<u64> words = {
        PVIA_MC_SHARING_WITNESS_DOMAIN,
        PVIA_MC_SHARING_WITNESS_VERSION,
        static_cast<u64>(witness.kind),
        static_cast<u64>(witness.payload_words.size())};
    append_digest(witness.sharing_binding, &words);
    words.insert(
        words.end(), witness.payload_words.begin(),
        witness.payload_words.end());
    return words;
}

bool decode_multiplication_consistency_sharing_witness(
    const std::vector<u64>& words,
    MultiplicationConsistencySharingWitnessEnvelope* witness) {
    if (!witness ||
        words.size() < PVIA_MC_SHARING_WITNESS_HEADER_WORDS ||
        words[0] != PVIA_MC_SHARING_WITNESS_DOMAIN ||
        words[1] != PVIA_MC_SHARING_WITNESS_VERSION ||
        words[2] < PVIA_MC_SHARING_KIND_VSS_LOCAL ||
        words[2] > PVIA_MC_SHARING_KIND_VSS_DEALER ||
        words[3] > static_cast<u64>(
            std::numeric_limits<size_t>::max()) ||
        words[3] != static_cast<u64>(
            words.size() - PVIA_MC_SHARING_WITNESS_HEADER_WORDS))
        return false;
    MultiplicationConsistencySharingWitnessEnvelope decoded;
    decoded.kind =
        static_cast<MultiplicationConsistencySharingWitnessKind>(words[2]);
    decoded.sharing_binding = read_digest(words, 4);
    decoded.payload_words.assign(
        words.begin() + PVIA_MC_SHARING_WITNESS_HEADER_WORDS,
        words.end());
    if (!validate_multiplication_consistency_sharing_witness(decoded))
        return false;
    *witness = std::move(decoded);
    return true;
}

bool wrap_reference_multiplication_consistency_sharing_witness(
    MultiplicationConsistencySharingWitnessKind kind,
    const std::vector<u64>& payload_words,
    const Digest& expected_binding,
    std::vector<u64>* encoded) {
    if (!encoded || expected_binding == Digest{}) return false;
    MultiplicationConsistencySharingWitnessEnvelope envelope;
    envelope.kind = kind;
    envelope.sharing_binding = expected_binding;
    envelope.payload_words = payload_words;
    *encoded = encode_multiplication_consistency_sharing_witness(envelope);
    return !encoded->empty();
}


bool wrap_reference_multiplication_consistency_input_sharing_witness(
    const std::vector<u64>& payload_words,
    const Digest& expected_binding,
    std::vector<u64>* encoded) {
    if (!encoded || payload_words.empty() ||
        expected_binding == Digest{})
        return false;
    ReferenceVssLocalWitness direct;
    if (decode_reference_vss_local_witness(payload_words, &direct)) {
        return wrap_reference_multiplication_consistency_sharing_witness(
            MultiplicationConsistencySharingWitnessKind::VSS_LOCAL,
            payload_words, expected_binding, encoded);
    }
    ReferenceLinearSharingProvenance linear;
    if (decode_reference_linear_sharing_provenance(
            payload_words, &linear)) {
        return wrap_reference_multiplication_consistency_sharing_witness(
            MultiplicationConsistencySharingWitnessKind::LINEAR_COMBINATION,
            payload_words, expected_binding, encoded);
    }
    return false;
}

} // namespace pvia
