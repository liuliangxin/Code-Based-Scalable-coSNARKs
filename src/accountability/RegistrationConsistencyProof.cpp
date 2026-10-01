#include "RegistrationConsistencyProof.hpp"

#include <cstring>

namespace pvia {
namespace {

constexpr u64 REG_STATEMENT_DOMAIN = 0x5056524547435354ULL; // PVREGCST
constexpr u64 REG_PROOF_DOMAIN = 0x5056524547505246ULL;     // PVREGPRF
constexpr u64 REG_SET_DOMAIN = 0x5056524547534554ULL;       // PVREGSET
constexpr u64 REG_CAP_DOMAIN = 0x5056524547434150ULL;       // PVREGCAP

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

} // namespace

Digest compute_registration_consistency_statement_binding(
    const RegistrationConsistencyStatement& statement) {
    std::vector<u64> words = {
        REG_STATEMENT_DOMAIN, statement.sid, statement.checkpoint,
        statement.ref.owner, statement.ref.object_id,
        static_cast<u64>(statement.kernel),
        static_cast<u64>(statement.state_element_count),
        static_cast<u64>(statement.output_element_count)};
    append_digest(statement.public_state_digest, &words);
    append_digest(statement.public_actual_digest, &words);
    append_digest(statement.operation_statement_binding, &words);
    append_digest(statement.sharing_transcript_binding, &words);
    return hash_words(words);
}

bool validate_registration_consistency_statement(
    const RegistrationConsistencyStatement& statement) {
    if (statement.sid == 0 || statement.checkpoint == 0 ||
        statement.kernel == AuditRelationKernel::UNKNOWN ||
        statement.state_element_count == 0 ||
        statement.output_element_count == 0 ||
        statement.public_state_digest == Digest{} ||
        statement.public_actual_digest == Digest{} ||
        statement.operation_statement_binding == Digest{} ||
        statement.sharing_transcript_binding == Digest{} ||
        statement.statement_binding == Digest{})
        return false;
    return statement.statement_binding ==
        compute_registration_consistency_statement_binding(statement);
}

Digest compute_registration_consistency_proof_commitment(
    const RegistrationConsistencyProofArtifact& proof) {
    std::vector<u64> words = {
        REG_PROOF_DOMAIN,
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

bool validate_registration_consistency_proof_artifact(
    const RegistrationConsistencyStatement& statement,
    const RegistrationConsistencyProofArtifact& proof) {
    if (!validate_registration_consistency_statement(statement) ||
        !proof.available || !proof.cryptographically_authenticated ||
        !proof.zero_knowledge || proof.proof_system_id == 0 ||
        proof.statement_binding != statement.statement_binding ||
        proof.transcript_binding == Digest{} || proof.proof_words.empty() ||
        proof.proof_commitment == Digest{})
        return false;
    return proof.proof_commitment ==
        compute_registration_consistency_proof_commitment(proof);
}
Digest compute_registration_consistency_set_binding(
    const std::vector<RegistrationConsistencyProofArtifact>& proofs) {
    if (proofs.empty()) return Digest{};
    std::vector<u64> words = {
        REG_SET_DOMAIN, static_cast<u64>(proofs.size())};
    for (const auto& proof : proofs) {
        if (!proof.available || !proof.cryptographically_authenticated ||
            !proof.zero_knowledge || proof.proof_system_id == 0 ||
            proof.statement_binding == Digest{} ||
            proof.transcript_binding == Digest{} ||
            proof.proof_words.empty() || proof.proof_commitment == Digest{} ||
            proof.proof_commitment !=
                compute_registration_consistency_proof_commitment(proof))
            return Digest{};
        append_digest(proof.proof_commitment, &words);
    }
    return hash_words(words);
}

Digest compute_registration_consistency_capability_binding(
    const RegistrationConsistencyCapabilities& capabilities) {
    std::vector<u64> words = {
        REG_CAP_DOMAIN,
        capabilities.available ? 1ULL : 0ULL,
        capabilities.malicious_sound ? 1ULL : 0ULL,
        capabilities.zero_knowledge ? 1ULL : 0ULL,
        capabilities.binds_sharing_transcript ? 1ULL : 0ULL,
        capabilities.protocol_id};
    append_digest(capabilities.implementation_binding, &words);
    return hash_words(words);
}
bool validate_registration_consistency_capabilities(
    const RegistrationConsistencyCapabilities& capabilities) {
    if (!capabilities.available || capabilities.protocol_id == 0 ||
        capabilities.implementation_binding == Digest{} ||
        capabilities.capability_binding == Digest{})
        return false;
    return capabilities.capability_binding ==
        compute_registration_consistency_capability_binding(capabilities);
}

bool production_ready_registration_consistency_capabilities(
    const RegistrationConsistencyCapabilities& capabilities) {
    return validate_registration_consistency_capabilities(capabilities) &&
        capabilities.malicious_sound && capabilities.zero_knowledge &&
        capabilities.binds_sharing_transcript;
}

RegistrationConsistencyCapabilities
FailClosedRegistrationConsistencyProofBackend::Capabilities() const {
    return RegistrationConsistencyCapabilities{};
}

RegistrationConsistencyProofArtifact
FailClosedRegistrationConsistencyProofBackend::Prove(
    const RegistrationConsistencyStatement& statement,
    const RegistrationConsistencyWitness&) const {
    RegistrationConsistencyProofArtifact proof;
    proof.statement_binding = statement.statement_binding;
    return proof;
}
bool FailClosedRegistrationConsistencyProofBackend::Verify(
    const RegistrationConsistencyStatement&,
    const RegistrationConsistencyProofArtifact&) const {
    return false;
}

} // namespace pvia
