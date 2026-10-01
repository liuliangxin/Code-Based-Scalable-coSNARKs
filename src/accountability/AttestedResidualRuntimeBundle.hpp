#pragma once

#include "AttestedResidualMpcBackend.hpp"
#include "ReferenceShamirResidualMpcBackend.hpp"
#include "PrivateResidualRegistry.hpp"
#include "MpiResidualActivationScopeSynchronizer.hpp"
#include "MultiplicationConsistencyBackendRegistry.hpp"

namespace pvia {

// Runtime composition for the MALICIOUS_ABORT residual sub-protocol.
// A caller supplies the private residual store, authenticated transport, and
// optionally a production multiplication-consistency proof backend. When the
// proof backend is absent or under-strength, the bundle stays fail closed.
class AttestedResidualRuntimeBundle final {
public:
    AttestedResidualRuntimeBundle(
        const PrivateResidualShareStore& store,
        const AuthenticatedMpcExchange& exchange,
        int rank, int world_size, int threshold,
        uint64_t session_id,
        const MultiplicationConsistencyProofBackend*
            consistency_backend = nullptr,
        MPI_Comm comm = MPI_COMM_WORLD,
        const MultiplicationConsistencyProviderAcceptanceResult*
            consistency_acceptance = nullptr);

    bool ready() const { return protocol_.ready(); }
    bool ActivateForScope(
        const ObligationSet& scope,
        const LocalResidualBatchView& local_view);
    bool ActivateForScope(
        const ObligationSet& scope,
        const PrivateResidualRegistry& registry);
    bool ActivateSealedCheckpoint(
        const AuditCheckpointView& checkpoint,
        const PrivateAuditMaterialStore& materials,
        const PrivateResidualRegistry& registry);
    bool ready_for_scope(const ObligationSet& scope) const;
    void ClearActivatedResiduals();

    const ObligationSet& last_activation_scope() const {
        return last_activation_scope_;
    }
    Digest last_activation_scope_sync_binding() const {
        return last_activation_scope_sync_binding_;
    }

    ReferenceShamirResidualMpcBackend& data_plane() { return data_plane_; }
    const ReferenceShamirResidualMpcBackend& data_plane() const {
        return data_plane_;
    }
    const AttestedResidualMpcBackend& attested_backend() const {
        return attested_backend_;
    }
    const MpcBackedAuthenticatedResidualProtocol& protocol() const {
        return protocol_;
    }
    const ProtocolBackedCollectiveResidualEngine& engine() const {
        return engine_;
    }
    ResidualMpcMaliciousSecurityCapabilities security_capabilities() const {
        return security_provider_.Capabilities();
    }
    Digest strong_consistency_capability_binding() const {
        return mpc_.multiplication_consistency_capability_binding();
    }

private:
    uint64_t session_id_ = 0;
    int rank_ = -1;
    int world_size_ = 0;
    const AuthenticatedMpcExchange& exchange_;
    uint64_t activation_sync_sequence_ = 1;
    ObligationSet last_activation_scope_{};
    Digest last_activation_scope_sync_binding_{};
    FailClosedMultiplicationConsistencyProofBackend fail_closed_consistency_;
    const MultiplicationConsistencyProofBackend& consistency_backend_;
    ScopedMultiplicationConsistencyBackendRegistration
        consistency_registration_;
    ReferenceShamirMpc mpc_;
    ReferenceShamirResidualMpcBackend data_plane_;
    ComposedResidualMpcMaliciousAbortSecurityProvider security_provider_;
    AttestedResidualMpcBackend attested_backend_;
    MpcBackedAuthenticatedResidualProtocol protocol_;
    ProtocolBackedCollectiveResidualEngine engine_;
};

} // namespace pvia
