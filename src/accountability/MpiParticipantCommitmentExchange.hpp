#pragma once

#include "AuthenticatedResidualProtocol.hpp"

namespace pvia {

// Transport-only helper for public commitment envelopes.  It does NOT provide
// cryptographic authentication; the caller must verify authentication material
// before setting CollectiveResidualCommitmentSet::cryptographically_authenticated.
class MpiParticipantCommitmentExchange {
public:
    static std::vector<ParticipantResidualCommitment> AllGather(
        const ParticipantResidualCommitment& local,
        int rank,
        int world_size);
};

} // namespace pvia
