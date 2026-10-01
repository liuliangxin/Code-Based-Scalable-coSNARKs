#include "ResidualChallengeTranscript.hpp"
#include "AuthenticatedResidualProtocol.hpp"

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

} // namespace

Digest compute_challenge_transcript_digest(
    const AuthenticatedChallengeTranscript& transcript) {
    std::vector<u64> words = {
        transcript.available ? 1ULL : 0ULL,
        transcript.cryptographically_authenticated ? 1ULL : 0ULL,
        transcript.checkpoint,
        static_cast<u64>(transcript.participant_count)
    };
    append_digest_words(transcript.scope_binding, words);
    append_digest_words(transcript.participant_commitment_root, words);
    append_digest_words(transcript.randomness_commitment, words);
    append_digest_words(transcript.challenge, words);
    if (transcript.security_attestation_binding != Digest{}) {
        words.push_back(RESIDUAL_SECURITY_LINK_MARKER);
        append_digest_words(transcript.security_attestation_binding, words);
    }
    append_digest_words(transcript.proof_commitment, words);
    return hash_words(words);
}

bool validate_challenge_transcript(
    const ObligationSet& scope,
    const CollectiveResidualCommitmentSet& commitments,
    const AuthenticatedChallengeTranscript& transcript,
    int world_size) {
    if (world_size <= 0) return false;
    if (!transcript.available || !transcript.cryptographically_authenticated)
        return false;
    if (transcript.checkpoint != scope.checkpoint ||
        transcript.checkpoint != commitments.checkpoint)
        return false;
    if (transcript.participant_count != static_cast<size_t>(world_size) ||
        transcript.participant_count != commitments.participants.size())
        return false;
    if (transcript.scope_binding != compute_collective_scope_binding(scope))
        return false;
    if (transcript.participant_commitment_root != commitments.root)
        return false;
    if (transcript.security_attestation_binding !=
        commitments.security_attestation_binding)
        return false;
    if (transcript.randomness_commitment == Digest{} ||
        transcript.challenge == Digest{} ||
        transcript.proof_commitment == Digest{})
        return false;
    return transcript.transcript_digest ==
           compute_challenge_transcript_digest(transcript);
}

} // namespace pvia
