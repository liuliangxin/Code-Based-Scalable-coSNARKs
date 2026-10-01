#pragma once

#include "PublicTransferCheckEngine.hpp"

namespace pvia {

// Transport-only dissemination for the public observation already selected by
// an authenticated transfer dispute. MPI does not authenticate the observation:
// every rank re-hashes the decoded record against public_evidence_binding.
class MpiPublicTransferObservationExchange {
public:
    static bool Resolve(
        const PublicTransferObservationStore& observations,
        const ObligationSet& scope,
        const CollectiveDisputeResult& dispute,
        int rank,
        int world_size,
        PublicTransferObservation* resolved);
};

} // namespace pvia
