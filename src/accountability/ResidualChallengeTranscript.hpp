#pragma once

#include "CollectiveResidualEngine.hpp"

namespace pvia {

struct CollectiveResidualCommitmentSet;

// Public transcript produced only after the residual commitment set is fixed.
// The clear/randomness-generation state remains inside the secure provider.
struct AuthenticatedChallengeTranscript {
    bool available = false;
    bool cryptographically_authenticated = false;
    CheckpointId checkpoint = 0;
    size_t participant_count = 0;
    Digest scope_binding{};
    Digest participant_commitment_root{};
    Digest randomness_commitment{};
    Digest challenge{};
    Digest security_attestation_binding{};
    Digest proof_commitment{};
    Digest transcript_digest{};
};

Digest compute_challenge_transcript_digest(
    const AuthenticatedChallengeTranscript& transcript);

bool validate_challenge_transcript(
    const ObligationSet& scope,
    const CollectiveResidualCommitmentSet& commitments,
    const AuthenticatedChallengeTranscript& transcript,
    int world_size);

} // namespace pvia
