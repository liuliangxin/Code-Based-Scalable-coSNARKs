#pragma once

#include "PublicTransferCheckEngine.hpp"

namespace pvia {

// Concrete transcript-direct transfer backend. It treats Ed25519-verified
// transfer metadata as the authentication boundary; MPI is used only to
// reconcile already-authenticated public facts across ranks.
class Ed25519PublicTransferCheckBackend final
    : public PublicTransferCheckBackend {
public:
    PublicTransferCheckResult Check(
        const ObligationSet& scope,
        const std::vector<PublicTransferObservation>& local_observations,
        int rank,
        int world_size) const override;

    CollectiveDisputeResult Dispute(
        const ObligationSet& scope,
        const PublicTransferCheckResult& check,
        const std::vector<PublicTransferObservation>& local_observations,
        int rank,
        int world_size) const override;
};

} // namespace pvia
