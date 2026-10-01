#pragma once

#include "PVIA.hpp"

namespace pvia {

// Synchronizes only the public obligation scope Q. No private residual, witness,
// or authenticated share is transmitted by this helper.
class MpiAuditScopeSynchronizer {
public:
    static ObligationSet Synchronize(
        const ObligationSet& local_scope,
        int rank,
        int world_size,
        int coordinator_rank = 0);

    // Secure-provider path: the coordinator authenticates the complete public
    // scope, then every rank authenticates the binding it received. Any
    // disagreement fails closed. This is agreement checking, not RB/GOD.
    static ObligationSet SynchronizeAuthenticated(
        const ObligationSet& local_scope,
        int rank,
        int world_size,
        uint64_t sync_sequence,
        int coordinator_rank = 0);
};

} // namespace pvia
