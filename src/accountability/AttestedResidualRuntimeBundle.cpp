#include "AttestedResidualRuntimeBundle.hpp"

namespace pvia {
namespace {

constexpr u64 RUNTIME_ACTIVATION_GATE_DOMAIN =
    0x5056524152544741ULL; // PVRARTGA
constexpr u64 RUNTIME_ACTIVATION_READY_KIND =
    0x5056524152524459ULL; // PVRARRDY

AuthenticatedMpcMessageContext make_activation_ready_context(
    const ObligationSet& scope, uint64_t sequence) {
    AuthenticatedMpcMessageContext context;
    context.protocol_domain = RUNTIME_ACTIVATION_GATE_DOMAIN;
    context.sid = scope.session_id;
    context.checkpoint = scope.checkpoint;
    context.round = scope.round;
    context.sequence = sequence;
    context.message_kind = RUNTIME_ACTIVATION_READY_KIND;
    return context;
}

} // namespace

AttestedResidualRuntimeBundle::AttestedResidualRuntimeBundle(
    const PrivateResidualShareStore& store,
    const AuthenticatedMpcExchange& exchange,
    int rank, int world_size, int threshold,
    uint64_t session_id,
    const MultiplicationConsistencyProofBackend* consistency_backend,
    MPI_Comm comm,
    const MultiplicationConsistencyProviderAcceptanceResult*
        consistency_acceptance)
    : session_id_(session_id),
      rank_(rank),
      world_size_(world_size),
      exchange_(exchange),
      consistency_backend_(
          MultiplicationConsistencyBackendRegistry::AcceptanceMatches(
              consistency_backend, consistency_acceptance)
              ? *consistency_backend
              : (MultiplicationConsistencyBackendRegistry::Current()
                    ? *MultiplicationConsistencyBackendRegistry::Current()
                    : static_cast<const MultiplicationConsistencyProofBackend&>(
                          fail_closed_consistency_))),
      consistency_registration_(
          MultiplicationConsistencyBackendRegistry::AcceptanceMatches(
              consistency_backend, consistency_acceptance)
              ? consistency_backend : nullptr,
          MultiplicationConsistencyBackendRegistry::AcceptanceMatches(
              consistency_backend, consistency_acceptance)
              ? consistency_acceptance : nullptr),
      mpc_(rank, world_size, threshold, comm, &consistency_backend_),
      data_plane_(store, mpc_, exchange),
      security_provider_(
          data_plane_.Capabilities().implementation_binding,
          consistency_backend_,
          data_plane_.Capabilities()
              .authenticated_channel_capability_binding),
      attested_backend_(
          data_plane_, security_provider_,
          RobustAuditSecurityLevel::MALICIOUS_ABORT),
      protocol_(
          attested_backend_,
          RobustAuditSecurityLevel::MALICIOUS_ABORT),
      engine_(protocol_) {}

bool AttestedResidualRuntimeBundle::ActivateForScope(
    const ObligationSet& scope,
    const LocalResidualBatchView& local_view) {
    if (!ready() || session_id_ == 0 ||
        scope.session_id != session_id_ || rank_ < 0 || world_size_ <= 0 ||
        rank_ >= world_size_)
        return false;
    if (!data_plane_.ActivateResiduals(
            scope, local_view, rank_, world_size_))
        return false;
    if (!protocol_.ready_for_scope(scope)) {
        data_plane_.ClearActivatedResiduals();
        return false;
    }
    return true;
}

bool AttestedResidualRuntimeBundle::ActivateForScope(
    const ObligationSet& scope,
    const PrivateResidualRegistry& registry) {
    const LocalResidualBatchView local_view =
        registry.BuildLocalBatchView(scope, static_cast<uint32_t>(rank_));
    if (!local_view.complete_for_owner || !local_view.all_authenticated)
        return false;
    return ActivateForScope(scope, local_view);
}

bool AttestedResidualRuntimeBundle::ActivateSealedCheckpoint(
    const AuditCheckpointView& checkpoint,
    const PrivateAuditMaterialStore& materials,
    const PrivateResidualRegistry& registry) {
    last_activation_scope_ = ObligationSet{};
    last_activation_scope_sync_binding_ = Digest{};
    if (session_id_ == 0 || rank_ < 0 || world_size_ <= 0 ||
        rank_ >= world_size_ || activation_sync_sequence_ == 0)
        return false;

    const uint64_t sync_sequence = activation_sync_sequence_++;
    const ResidualActivationScopeSyncResult synchronized =
        MpiResidualActivationScopeSynchronizer::
            BuildAndSynchronizeAuthenticated(
                checkpoint, materials, session_id_, exchange_,
                rank_, world_size_, sync_sequence);
    if (!synchronized.available || synchronized.binding == Digest{})
        return false;

    last_activation_scope_ = synchronized.scope;
    last_activation_scope_sync_binding_ = synchronized.binding;
    if (synchronized.scope.operations.empty()) {
        data_plane_.ClearActivatedResiduals();
        return true;
    }

    const LocalResidualBatchView local_view = registry.BuildLocalBatchView(
        synchronized.scope, static_cast<uint32_t>(rank_));
    const bool local_ready = ready() && local_view.complete_for_owner &&
                             local_view.all_authenticated;
    bool all_ready = false;
    Digest ready_binding{};
    if (!exchange_.AllTrue(
            make_activation_ready_context(
                synchronized.scope, sync_sequence),
            local_ready, &all_ready, &ready_binding) ||
        !all_ready || ready_binding == Digest{}) {
        data_plane_.ClearActivatedResiduals();
        return false;
    }
    if (!ActivateForScope(synchronized.scope, local_view)) {
        data_plane_.ClearActivatedResiduals();
        return false;
    }
    return true;
}

bool AttestedResidualRuntimeBundle::ready_for_scope(
    const ObligationSet& scope) const {
    return protocol_.ready_for_scope(scope);
}

void AttestedResidualRuntimeBundle::ClearActivatedResiduals() {
    data_plane_.ClearActivatedResiduals();
    last_activation_scope_ = ObligationSet{};
    last_activation_scope_sync_binding_ = Digest{};
}

} // namespace pvia
