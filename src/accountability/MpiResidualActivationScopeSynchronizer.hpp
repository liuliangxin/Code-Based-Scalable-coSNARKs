#pragma once

#include "AuthenticatedMpcExchange.hpp"
#include "ResidualActivationScope.hpp"

namespace pvia {

struct ResidualActivationScopeSyncResult {
    bool available = false;
    ObligationSet scope{};
    Digest preflight_transcript_binding{};
    Digest metadata_transcript_binding{};
    Digest descriptor_transcript_binding{};
    Digest binding{};
};

// Pre-failure canonicalization of local private-residual fragments. Only public
// operation references and obligation classes are exchanged; private residual
// values and shares never cross this boundary.
class MpiResidualActivationScopeSynchronizer final {
public:
    static ResidualActivationScopeSyncResult SynchronizeAuthenticated(
        const ObligationSet& local_fragment,
        const AuthenticatedMpcExchange& exchange,
        int rank, int world_size,
        uint64_t sync_sequence);

    static ResidualActivationScopeSyncResult BuildAndSynchronizeAuthenticated(
        const AuditCheckpointView& checkpoint,
        const PrivateAuditMaterialStore& materials,
        uint64_t expected_session_id,
        const AuthenticatedMpcExchange& exchange,
        int rank, int world_size,
        uint64_t sync_sequence);
};

} // namespace pvia
