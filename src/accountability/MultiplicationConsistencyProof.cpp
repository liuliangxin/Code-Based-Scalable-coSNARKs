#include "MultiplicationConsistencyProof.hpp"
#include "MultiplicationConsistencyProviderAbiC.h"
#include "MultiplicationConsistencySharingWitness.hpp"

#include <cstring>
#include <limits>

namespace pvia {
namespace {

constexpr u64 MUL_STATEMENT_DOMAIN = PVIA_MC_STATEMENT_BINDING_DOMAIN;
constexpr u64 MUL_PROOF_DOMAIN = PVIA_MC_PROOF_COMMITMENT_DOMAIN;
constexpr u64 MUL_CAP_DOMAIN = PVIA_MC_CAPABILITY_BINDING_DOMAIN;
constexpr u64 MUL_SET_DOMAIN = 0x50564d554c534554ULL;       // PVMULSET

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
    if (offset > words.size() || words.size() - offset < 4) return digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}

} // namespace

Digest compute_multiplication_consistency_statement_binding(
    const MultiplicationConsistencyStatement& statement) {
    std::vector<u64> words = {
        MUL_STATEMENT_DOMAIN,
        statement.sid,
        statement.checkpoint,
        statement.multiplication_id,
        statement.dealer};
    append_digest(statement.lhs_sharing_binding, &words);
    append_digest(statement.rhs_sharing_binding, &words);
    append_digest(statement.output_sharing_binding, &words);
    append_digest(statement.context_binding, &words);
    return hash_words(words);
}

bool validate_multiplication_consistency_statement(
    const MultiplicationConsistencyStatement& statement) {
    if (statement.sid == 0 || statement.checkpoint == 0 ||
        statement.multiplication_id == 0 ||
        statement.lhs_sharing_binding == Digest{} ||
        statement.rhs_sharing_binding == Digest{} ||
        statement.output_sharing_binding == Digest{} ||
        statement.context_binding == Digest{} ||
        statement.statement_binding == Digest{})
        return false;
    return statement.statement_binding ==
        compute_multiplication_consistency_statement_binding(statement);
}
bool validate_multiplication_consistency_witness_for_statement(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyWitness& witness) {
    const auto canonical_field = [](const F& value) {
        return value.real < PVIA_MC_FIELD_MODULUS &&
               value.img < PVIA_MC_FIELD_MODULUS;
    };
    if (F::mod != PVIA_MC_FIELD_MODULUS ||
        !validate_multiplication_consistency_statement(statement) ||
        !canonical_field(witness.lhs_share) ||
        !canonical_field(witness.rhs_share) ||
        !canonical_field(witness.product_value) ||
        witness.product_value != witness.lhs_share * witness.rhs_share)
        return false;

    MultiplicationConsistencySharingWitnessEnvelope lhs;
    MultiplicationConsistencySharingWitnessEnvelope rhs;
    MultiplicationConsistencySharingWitnessEnvelope output;
    if (!decode_multiplication_consistency_sharing_witness(
            witness.lhs_sharing_witness_words, &lhs) ||
        !decode_multiplication_consistency_sharing_witness(
            witness.rhs_sharing_witness_words, &rhs) ||
        !decode_multiplication_consistency_sharing_witness(
            witness.output_sharing_witness_words, &output))
        return false;

    const auto input_kind_ok = [](
        MultiplicationConsistencySharingWitnessKind kind) {
        return kind ==
                   MultiplicationConsistencySharingWitnessKind::VSS_LOCAL ||
               kind ==
                   MultiplicationConsistencySharingWitnessKind::
                       LINEAR_COMBINATION;
    };
    return input_kind_ok(lhs.kind) && input_kind_ok(rhs.kind) &&
        output.kind ==
            MultiplicationConsistencySharingWitnessKind::VSS_DEALER &&
        lhs.sharing_binding == statement.lhs_sharing_binding &&
        rhs.sharing_binding == statement.rhs_sharing_binding &&
        output.sharing_binding == statement.output_sharing_binding;
}

Digest compute_multiplication_consistency_proof_commitment(
    const MultiplicationConsistencyProofArtifact& proof) {
    std::vector<u64> words = {
        MUL_PROOF_DOMAIN,
        proof.available ? 1ULL : 0ULL,
        proof.cryptographically_authenticated ? 1ULL : 0ULL,
        proof.zero_knowledge ? 1ULL : 0ULL,
        proof.proof_system_id,
        static_cast<u64>(proof.proof_words.size())};
    append_digest(proof.statement_binding, &words);
    append_digest(proof.transcript_binding, &words);
    words.insert(words.end(), proof.proof_words.begin(), proof.proof_words.end());
    return hash_words(words);
}

bool validate_multiplication_consistency_proof_artifact(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyProofArtifact& proof) {
    if (!validate_multiplication_consistency_statement(statement) ||
        !proof.available || !proof.cryptographically_authenticated ||
        !proof.zero_knowledge || proof.proof_system_id == 0 ||
        proof.statement_binding != statement.statement_binding ||
        proof.transcript_binding == Digest{} || proof.proof_words.empty() ||
        proof.proof_commitment == Digest{})
        return false;
    return proof.proof_commitment ==
        compute_multiplication_consistency_proof_commitment(proof);
}

std::vector<u64> encode_multiplication_consistency_proof_artifact(
    const MultiplicationConsistencyProofArtifact& proof) {
    std::vector<u64> words = {
        proof.available ? 1ULL : 0ULL,
        proof.cryptographically_authenticated ? 1ULL : 0ULL,
        proof.zero_knowledge ? 1ULL : 0ULL,
        proof.proof_system_id};
    append_digest(proof.statement_binding, &words);
    append_digest(proof.transcript_binding, &words);
    append_digest(proof.proof_commitment, &words);
    words.push_back(static_cast<u64>(proof.proof_words.size()));
    words.insert(words.end(), proof.proof_words.begin(), proof.proof_words.end());
    return words;
}

bool decode_multiplication_consistency_proof_artifact(
    const std::vector<u64>& words,
    MultiplicationConsistencyProofArtifact* proof) {
    if (!proof || words.size() < 17) return false;
    if (words[0] > 1 || words[1] > 1 || words[2] > 1 ||
        words[3] > static_cast<u64>(std::numeric_limits<uint32_t>::max()))
        return false;
    const u64 proof_words = words[16];
    if (proof_words != static_cast<u64>(words.size() - 17)) return false;
    MultiplicationConsistencyProofArtifact decoded;
    decoded.available = words[0] != 0;
    decoded.cryptographically_authenticated = words[1] != 0;
    decoded.zero_knowledge = words[2] != 0;
    decoded.proof_system_id = static_cast<uint32_t>(words[3]);
    decoded.statement_binding = read_digest(words, 4);
    decoded.transcript_binding = read_digest(words, 8);
    decoded.proof_commitment = read_digest(words, 12);
    decoded.proof_words.assign(words.begin() + 17, words.end());
    *proof = decoded;
    return true;
}

Digest compute_multiplication_consistency_set_binding(
    const std::vector<MultiplicationConsistencyProofArtifact>& proofs) {
    if (proofs.empty()) return Digest{};
    std::vector<u64> words = {
        MUL_SET_DOMAIN, static_cast<u64>(proofs.size())};
    for (const auto& proof : proofs) {
        if (!proof.available || !proof.cryptographically_authenticated ||
            !proof.zero_knowledge || proof.proof_system_id == 0 ||
            proof.statement_binding == Digest{} ||
            proof.transcript_binding == Digest{} || proof.proof_words.empty() ||
            proof.proof_commitment == Digest{} ||
            proof.proof_commitment !=
                compute_multiplication_consistency_proof_commitment(proof))
            return Digest{};
        append_digest(proof.proof_commitment, &words);
    }
    return hash_words(words);
}

Digest compute_multiplication_consistency_relation_binding() {
    const std::vector<u64> words = {
        PVIA_MC_RELATION_BINDING_DOMAIN,
        PVIA_MC_RELATION_VERSION,
        static_cast<u64>(PVIA_MC_ABI_VERSION),
        PVIA_MC_FIELD_MODULUS,
        static_cast<u64>(PVIA_MC_FIELD_COMPONENT_WORDS),
        PVIA_MC_FIELD_EXTENSION_I_SQUARED_IS_NEG_ONE,
        PVIA_MC_STATEMENT_BINDING_DOMAIN,
        PVIA_MC_STATEMENT_ABI_DOMAIN,
        static_cast<u64>(PVIA_MC_STATEMENT_WORDS),
        PVIA_MC_WITNESS_ABI_DOMAIN,
        static_cast<u64>(PVIA_MC_WITNESS_HEADER_WORDS),
        PVIA_MC_SHARING_WITNESS_DOMAIN,
        PVIA_MC_SHARING_WITNESS_VERSION,
        PVIA_MC_SHARING_KIND_VSS_LOCAL,
        PVIA_MC_SHARING_KIND_LINEAR_COMBINATION,
        PVIA_MC_SHARING_KIND_VSS_DEALER,
        PVIA_MC_VSS_TRANSCRIPT_DOMAIN,
        PVIA_MC_VSS_DEALER_WITNESS_DOMAIN,
        PVIA_MC_VSS_LOCAL_WITNESS_DOMAIN,
        PVIA_MC_VSS_WITNESS_VERSION,
        static_cast<u64>(PVIA_MC_VSS_DEALER_FIXED_WORDS),
        static_cast<u64>(PVIA_MC_VSS_LOCAL_FIXED_WORDS),
        PVIA_MC_LINEAR_BINDING_DOMAIN,
        PVIA_MC_LINEAR_WITNESS_DOMAIN,
        static_cast<u64>(PVIA_MC_LINEAR_FIXED_WORDS)};
    return hash_words(words);
}

Digest compute_multiplication_consistency_capability_binding(
    const MultiplicationConsistencyCapabilities& capabilities) {
    std::vector<u64> words = {
        MUL_CAP_DOMAIN,
        capabilities.available ? 1ULL : 0ULL,
        capabilities.malicious_sound ? 1ULL : 0ULL,
        capabilities.zero_knowledge ? 1ULL : 0ULL,
        capabilities.binds_input_sharings ? 1ULL : 0ULL,
        capabilities.binds_output_sharing ? 1ULL : 0ULL,
        capabilities.protocol_id};
    append_digest(capabilities.relation_binding, &words);
    append_digest(capabilities.implementation_binding, &words);
    return hash_words(words);
}

bool validate_multiplication_consistency_capabilities(
    const MultiplicationConsistencyCapabilities& capabilities) {
    const Digest expected_relation =
        compute_multiplication_consistency_relation_binding();
    if (!capabilities.available || capabilities.protocol_id == 0 ||
        expected_relation == Digest{} ||
        capabilities.relation_binding != expected_relation ||
        capabilities.implementation_binding == Digest{} ||
        capabilities.capability_binding == Digest{})
        return false;
    return capabilities.capability_binding ==
        compute_multiplication_consistency_capability_binding(capabilities);
}
bool production_ready_multiplication_consistency_capabilities(
    const MultiplicationConsistencyCapabilities& capabilities) {
    return validate_multiplication_consistency_capabilities(capabilities) &&
        capabilities.malicious_sound && capabilities.zero_knowledge &&
        capabilities.binds_input_sharings &&
        capabilities.binds_output_sharing;
}

MultiplicationConsistencyCapabilities
FailClosedMultiplicationConsistencyProofBackend::Capabilities() const {
    return MultiplicationConsistencyCapabilities{};
}

MultiplicationConsistencyProofArtifact
FailClosedMultiplicationConsistencyProofBackend::Prove(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyWitness&) const {
    MultiplicationConsistencyProofArtifact proof;
    proof.statement_binding = statement.statement_binding;
    return proof;
}

bool FailClosedMultiplicationConsistencyProofBackend::Verify(
    const MultiplicationConsistencyStatement&,
    const MultiplicationConsistencyProofArtifact&) const {
    return false;
}

} // namespace pvia
