#include "ReferenceShamirResidualMpcBackend.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

namespace pvia {
namespace {

constexpr u64 REFERENCE_RESIDUAL_MPC_PROTOCOL_ID = 0x50565253484d5031ULL; // PVRSHMP1
constexpr u64 REFERENCE_RESIDUAL_MPC_IMPL_DOMAIN = 0x50565253484d494dULL; // PVRSHMIM
constexpr u64 REFERENCE_RESIDUAL_COMMIT_DOMAIN = 0x5056525348434f4dULL; // PVRSHCOM
constexpr u64 REFERENCE_RESIDUAL_CHALLENGE_DOMAIN = 0x505652534843484cULL; // PVRSHCHL
constexpr u64 REFERENCE_RESIDUAL_BATCH_DOMAIN = 0x5056525348424154ULL; // PVRSHBAT
constexpr u64 REFERENCE_RESIDUAL_SUBSET_DOMAIN = 0x5056525348535542ULL; // PVRSHSUB
constexpr u64 REFERENCE_RESIDUAL_LOCALIZE_DOMAIN = 0x50565253484c4f43ULL; // PVRSHLOC
constexpr u64 AUTH_KIND_COMMITMENTS = 0x5253434f4d4d4954ULL; // RSCOMMIT
constexpr u64 AUTH_KIND_LOCALIZATION = 0x52534c4f43414c31ULL; // RSLOCAL1
constexpr u64 AUTH_KIND_COMMIT_READY = 0x5253434d52445931ULL; // RSCMRDY1
constexpr u64 AUTH_KIND_CHALLENGE_READY = 0x5253434852445931ULL; // RSCHRDY1
constexpr u64 AUTH_KIND_BATCH_READY = 0x5253425452445931ULL; // RSBTRDY1
constexpr u64 AUTH_KIND_SUBSET_READY = 0x5253534252445931ULL; // RSSBRDY1
constexpr u64 AUTH_KIND_LOCALIZE_READY = 0x52534c4352445931ULL; // RSLCRDY1
constexpr u64 REFERENCE_RESIDUAL_ACTIVATION_DOMAIN = 0x5056525348414354ULL; // PVRSH ACT
constexpr u64 AUTH_KIND_ACTIVATE_READY = 0x5253414354524459ULL; // RSACTRDY
constexpr u64 AUTH_KIND_ACTIVATE_OPERATION_READY = 0x5253414f50524459ULL; // RSAOPRDY
constexpr u64 AUTH_KIND_ACTIVATE_DESCRIPTOR = 0x5253414354444553ULL; // RSACTDES
constexpr u64 AUTH_KIND_ACTIVATE_FINAL = 0x525341435446494eULL; // RSACTFIN
constexpr u64 AUTH_KIND_ACTIVATE_VSS = 0x5253414354565353ULL; // RSACTVSS
constexpr u64 REFERENCE_RESIDUAL_STRONG_ZERO_DOMAIN = 0x5056525354525a52ULL; // PVRSTRZR

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

uint64_t nonzero_digest_word(const Digest& digest) {
    uint64_t word = 0;
    std::memcpy(&word, digest.bytes.data(), sizeof(word));
    return word == 0 ? 1ULL : word;
}

Digest digest_from_words(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    if (offset > words.size() || words.size() - offset < 4) return digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}

F digest_to_field(const Digest& digest) {
    u64 real = 0;
    u64 imag = 0;
    std::memcpy(&real, digest.bytes.data(), 8);
    std::memcpy(&imag, digest.bytes.data() + 8, 8);
    return F(static_cast<long long>(real % F::mod),
             static_cast<long long>(imag % F::mod));
}

bool same_ref(const OperationRef& lhs, const OperationRef& rhs) {
    return lhs.owner == rhs.owner && lhs.object_id == rhs.object_id;
}

bool operation_less(const OperationRef& lhs, const OperationRef& rhs) {
    if (lhs.owner != rhs.owner) return lhs.owner < rhs.owner;
    return lhs.object_id < rhs.object_id;
}

const PrivateResidualHandle* find_handle(
    const LocalResidualBatchView& view, const OperationRef& ref) {
    for (const auto& handle : view.handles)
        if (same_ref(handle.ref, ref)) return &handle;
    return nullptr;
}

Digest bind_words(u64 domain, const std::vector<Digest>& digests,
                  const std::vector<u64>& suffix = {}) {
    std::vector<u64> words = {domain, static_cast<u64>(digests.size())};
    for (const Digest& digest : digests) append_digest(digest, &words);
    words.insert(words.end(), suffix.begin(), suffix.end());
    return hash_words(words);
}

} // namespace

ReferenceShamirResidualMpcBackend::ReferenceShamirResidualMpcBackend(
    const PrivateResidualShareStore& store,
    ReferenceShamirMpc& mpc,
    const AuthenticatedMpcExchange& exchange)
    : store_(store), mpc_(mpc), exchange_(exchange) {}

ResidualMpcCapabilities
ReferenceShamirResidualMpcBackend::Capabilities() const {
    ResidualMpcCapabilities c;
    if (!mpc_.valid() || !exchange_.production_authenticated_ready()) {
        return c;
    }
    c.available = true;
    c.protocol_id = REFERENCE_RESIDUAL_MPC_PROTOCOL_ID;
    c.security_level = RobustAuditSecurityLevel::REFERENCE_PASSIVE;
    c.malicious_secure = false;
    c.activation_before_failure = true;
    c.authenticated_channels = true;
    c.private_residual_sharing = true;
    c.commit_before_challenge = true;
    c.joint_unpredictable_challenge = true;
    c.random_linear_batch_check = true;
    c.masked_zero_test = true;
    c.recursive_subset_localization = true;
    c.publicly_identifiable_abort = false;
    c.guaranteed_output_delivery = false;
    c.authenticated_channel_capability_binding =
        exchange_.ProductionCapabilityBinding();
    c.identifiable_abort_capability_binding = Digest{};
    c.delivery_capability_binding = Digest{};
    c.implementation_binding = bind_words(
        REFERENCE_RESIDUAL_MPC_IMPL_DOMAIN,
        {c.authenticated_channel_capability_binding},
        {static_cast<u64>(mpc_.world_size()),
         static_cast<u64>(mpc_.threshold())});
    c.capability_binding = compute_residual_mpc_capability_binding(c);
    return c;
}

ResidualMpcPrecommitSecurityContext
ReferenceShamirResidualMpcBackend::PrecommitSecurityContext(
    const ObligationSet& scope) const {
    ResidualMpcPrecommitSecurityContext context;
    if (!HasActivatedVssProvenance(scope)) return context;
    const Digest strong_binding =
        mpc_.multiplication_consistency_capability_binding();
    if (activation_binding_ == Digest{} || strong_binding == Digest{})
        return context;
    context.available = true;
    context.activation_binding = activation_binding_;
    context.strong_consistency_capability_binding = strong_binding;
    return context;
}

bool ReferenceShamirResidualMpcBackend::EnsureTransport(
    const ObligationSet& scope, int rank, int world_size) const {
    if (scope.session_id == 0 || scope.checkpoint == 0 ||
        rank != mpc_.rank() || world_size != mpc_.world_size() ||
        rank < 0 || rank >= world_size ||
        !exchange_.production_authenticated_ready())
        return false;
    if (active_sid_ == scope.session_id &&
        active_checkpoint_ == scope.checkpoint &&
        mpc_.authenticated_transport_available())
        return true;
    if (!mpc_.SetAuthenticatedTransport(
            &exchange_, scope.session_id, scope.checkpoint))
        return false;
    active_sid_ = scope.session_id;
    active_checkpoint_ = scope.checkpoint;
    exchange_sequence_ = 1;
    return true;
}

bool ReferenceShamirResidualMpcBackend::ValidateLocalView(
    const LocalResidualBatchView& local_view, int rank) const {
    if (!local_view.complete_for_owner || !local_view.all_authenticated ||
        local_view.local_owner != static_cast<uint32_t>(rank))
        return false;
    for (const auto& handle : local_view.handles) {
        const PrivateResidualShare* share = store_.Find(handle.ref);
        if (!share || !validate_private_residual_share(*share) ||
            share->ref.owner != static_cast<uint32_t>(rank) ||
            share->commitment != handle.commitment ||
            share->checkpoint != handle.checkpoint ||
            share->relation != handle.relation ||
            share->kernel != handle.kernel ||
            share->label.sid != handle.label.sid ||
            share->label.phase != handle.label.phase ||
            share->label.round != handle.label.round ||
            share->label.owner != handle.label.owner ||
            share->label.obligation != handle.label.obligation ||
            share->label.object_id != handle.label.object_id ||
            !share->authenticated)
            return false;
    }
    return true;
}

void ReferenceShamirResidualMpcBackend::ClearActivatedResiduals() {
    activated_sid_ = 0;
    activated_checkpoint_ = 0;
    activated_scope_binding_ = Digest{};
    activation_binding_ = Digest{};
    activated_operations_.clear();
}

const ReferenceShamirResidualMpcBackend::ActivatedResidualOperation*
ReferenceShamirResidualMpcBackend::FindActivated(
    const OperationRef& ref) const {
    for (const auto& operation : activated_operations_)
        if (same_ref(operation.ref, ref)) return &operation;
    return nullptr;
}

bool ReferenceShamirResidualMpcBackend::HasActivatedResiduals(
    const ObligationSet& scope) const {
    if (activated_sid_ == 0 || activated_checkpoint_ == 0 ||
        activation_binding_ == Digest{} || activated_operations_.empty() ||
        activated_sid_ != scope.session_id ||
        activated_checkpoint_ != scope.checkpoint ||
        activated_scope_binding_ != compute_collective_scope_binding(scope) ||
        activated_operations_.size() != scope.operations.size())
        return false;
    for (const OperationRef& ref : scope.operations)
        if (!FindActivated(ref)) return false;
    return true;
}

bool ReferenceShamirResidualMpcBackend::HasActivatedVssProvenance(
    const ObligationSet& scope) const {
    if (!HasActivatedResiduals(scope)) return false;
    for (const auto& operation : activated_operations_) {
        if (operation.sharing_binding == Digest{} ||
            operation.local_shares.empty() ||
            !validate_reference_vss_local_witness(operation.local_witness) ||
            operation.local_witness.dealer !=
                static_cast<int>(operation.ref.owner) ||
            operation.local_witness.participant != mpc_.rank() ||
            operation.local_witness.element_count !=
                operation.local_shares.size() ||
            operation.local_witness.transcript_binding !=
                operation.sharing_binding)
            return false;
    }
    return true;
}

bool ReferenceShamirResidualMpcBackend::ValidateActivatedLocalView(
    const LocalResidualBatchView& local_view, int rank) const {
    if (!local_view.complete_for_owner || !local_view.all_authenticated ||
        local_view.local_owner != static_cast<uint32_t>(rank) ||
        activated_scope_binding_ !=
            compute_collective_scope_binding(local_view.scope))
        return false;
    size_t expected = 0;
    for (const auto& operation : activated_operations_)
        if (operation.ref.owner == static_cast<uint32_t>(rank)) ++expected;
    if (local_view.handles.size() != expected) return false;
    for (const auto& handle : local_view.handles) {
        const ActivatedResidualOperation* operation = FindActivated(handle.ref);
        if (!operation || operation->ref.owner != static_cast<uint32_t>(rank) ||
            operation->source_commitment != handle.commitment ||
            operation->checkpoint != handle.checkpoint ||
            operation->relation != handle.relation ||
            operation->kernel != handle.kernel ||
            operation->label.sid != handle.label.sid ||
            operation->label.phase != handle.label.phase ||
            operation->label.round != handle.label.round ||
            operation->label.owner != handle.label.owner ||
            operation->label.obligation != handle.label.obligation ||
            operation->label.object_id != handle.label.object_id)
            return false;
    }
    return true;
}

bool ReferenceShamirResidualMpcBackend::ActivateResiduals(
    const ObligationSet& scope,
    const LocalResidualBatchView& local_view,
    int rank, int world_size) {
    ClearActivatedResiduals();
    if (!EnsureTransport(scope, rank, world_size) || scope.operations.empty())
        return false;
    const bool local_ready = ValidateLocalView(local_view, rank);
    bool all_ready = false;
    Digest ready_binding{};
    if (!exchange_.AllTrue(
            NextContext(scope, AUTH_KIND_ACTIVATE_READY),
            local_ready, &all_ready, &ready_binding) ||
        !all_ready || ready_binding == Digest{})
        return false;

    ReferenceBivariateVss vss(
        rank, world_size, mpc_.threshold(), MPI_COMM_WORLD);
    if (!vss.valid()) return false;

    std::vector<OperationRef> refs = scope.operations;
    std::sort(refs.begin(), refs.end(), operation_less);
    if (std::adjacent_find(refs.begin(), refs.end()) != refs.end())
        return false;
    std::vector<ActivatedResidualOperation> activated;
    std::vector<Digest> descriptor_bindings;
    activated.reserve(refs.size());
    descriptor_bindings.reserve(refs.size());

    for (const OperationRef& ref : refs) {
        std::vector<u64> payload;
        std::vector<F> plaintext;
        bool owner_ready = true;
        if (rank == static_cast<int>(ref.owner)) {
            const PrivateResidualShare* share = store_.Find(ref);
            const PrivateResidualHandle* handle = find_handle(local_view, ref);
            owner_ready = share && handle &&
                validate_private_residual_share(*share) && share->authenticated &&
                share->commitment == handle->commitment &&
                share->checkpoint == scope.checkpoint && share->ref == ref &&
                share->label.sid == scope.session_id &&
                share->expected != Digest{} && share->actual != Digest{} &&
                share->operation_statement_binding != Digest{} &&
                !share->values.empty();
            if (owner_ready) {
                plaintext = share->values;
                payload = {
                    ref.owner, ref.object_id, share->label.sid,
                    static_cast<u64>(share->label.phase), share->label.round,
                    static_cast<u64>(share->label.obligation),
                    static_cast<u64>(share->relation),
                    static_cast<u64>(share->kernel), share->checkpoint,
                    static_cast<u64>(share->values.size())};
                append_digest(share->expected, &payload);
                append_digest(share->actual, &payload);
                append_digest(share->operation_statement_binding, &payload);
                append_digest(share->commitment, &payload);
            }
        }
        bool operation_ready = false;
        Digest operation_ready_binding{};
        if (!exchange_.AllTrue(
                NextContext(scope, AUTH_KIND_ACTIVATE_OPERATION_READY,
                            ref.object_id),
                owner_ready, &operation_ready, &operation_ready_binding) ||
            !operation_ready || operation_ready_binding == Digest{})
            return false;

        std::vector<u64> descriptor;
        Digest descriptor_transport{};
        if (!exchange_.BroadcastWords(
                NextContext(scope, AUTH_KIND_ACTIVATE_DESCRIPTOR,
                            ref.object_id),
                static_cast<int>(ref.owner), payload, &descriptor,
                &descriptor_transport) ||
            descriptor.size() != 26 || descriptor_transport == Digest{})
            return false;
        if (descriptor[0] != ref.owner || descriptor[1] != ref.object_id ||
            descriptor[2] != scope.session_id || descriptor[8] != scope.checkpoint ||
            descriptor[9] == 0)
            return false;

        ActivatedResidualOperation operation;
        operation.ref = ref;
        operation.label.sid = descriptor[2];
        operation.label.phase = static_cast<Phase>(descriptor[3]);
        operation.label.round = static_cast<uint32_t>(descriptor[4]);
        operation.label.owner = static_cast<uint32_t>(descriptor[0]);
        operation.label.obligation = static_cast<Obligation>(descriptor[5]);
        operation.label.object_id = descriptor[1];
        operation.relation = static_cast<RelationKind>(descriptor[6]);
        operation.kernel = static_cast<AuditRelationKernel>(descriptor[7]);
        operation.checkpoint = descriptor[8];
        operation.expected = digest_from_words(descriptor, 10);
        operation.actual = digest_from_words(descriptor, 14);
        operation.operation_statement_binding = digest_from_words(descriptor, 18);
        operation.source_commitment = digest_from_words(descriptor, 22);
        if (operation.expected == Digest{} || operation.actual == Digest{} ||
            operation.operation_statement_binding == Digest{} ||
            operation.source_commitment == Digest{})
            return false;

        ReferenceVssReceipt vss_receipt;
        if (!vss.ShareVectorFromDealerAuthenticated(
                static_cast<int>(ref.owner), plaintext,
                &operation.local_shares, &vss_receipt,
                exchange_,
                NextContext(scope, AUTH_KIND_ACTIVATE_VSS, ref.object_id),
                nullptr, &operation.local_witness) ||
            operation.local_shares.size() !=
                static_cast<size_t>(descriptor[9]) ||
            !vss_receipt.available || !vss_receipt.consistent ||
            vss_receipt.element_count != operation.local_shares.size() ||
            vss_receipt.transcript_binding == Digest{} ||
            !validate_reference_vss_local_witness(operation.local_witness) ||
            operation.local_witness.transcript_binding !=
                vss_receipt.transcript_binding)
            return false;
        operation.sharing_binding = vss_receipt.transcript_binding;
        operation.descriptor_binding = bind_words(
            REFERENCE_RESIDUAL_ACTIVATION_DOMAIN,
            {operation.expected, operation.actual,
             operation.operation_statement_binding,
             operation.source_commitment, operation.sharing_binding,
             descriptor_transport, operation_ready_binding},
            {ref.owner, ref.object_id, descriptor[9]});
        if (operation.descriptor_binding == Digest{}) return false;
        descriptor_bindings.push_back(operation.descriptor_binding);
        activated.push_back(std::move(operation));
    }

    const Digest scope_binding = compute_collective_scope_binding(scope);
    const Digest candidate = bind_words(
        REFERENCE_RESIDUAL_ACTIVATION_DOMAIN,
        descriptor_bindings,
        {scope.session_id, scope.checkpoint,
         static_cast<u64>(activated.size())});
    std::vector<u64> local_candidate;
    append_digest(candidate, &local_candidate);
    std::vector<u64> gathered;
    Digest final_transport{};
    if (candidate == Digest{} ||
        !exchange_.AllGatherWords(
            NextContext(scope, AUTH_KIND_ACTIVATE_FINAL),
            local_candidate, &gathered, &final_transport) ||
        gathered.size() != static_cast<size_t>(world_size) * 4 ||
        final_transport == Digest{})
        return false;
    for (int peer = 0; peer < world_size; ++peer)
        if (digest_from_words(gathered, static_cast<size_t>(peer) * 4) != candidate)
            return false;

    activated_sid_ = scope.session_id;
    activated_checkpoint_ = scope.checkpoint;
    activated_scope_binding_ = scope_binding;
    activation_binding_ = bind_words(
        REFERENCE_RESIDUAL_ACTIVATION_DOMAIN,
        {candidate, scope_binding, final_transport,
         exchange_.ProductionCapabilityBinding(), ready_binding},
        {static_cast<u64>(activated.size())});
    if (activation_binding_ == Digest{}) {
        ClearActivatedResiduals();
        return false;
    }
    activated_operations_ = std::move(activated);
    return HasActivatedVssProvenance(scope);
}

AuthenticatedMpcMessageContext
ReferenceShamirResidualMpcBackend::NextContext(
    const ObligationSet& scope, u64 message_kind, uint64_t round) const {
    AuthenticatedMpcMessageContext context;
    context.protocol_domain = REFERENCE_RESIDUAL_MPC_PROTOCOL_ID;
    context.sid = scope.session_id;
    context.checkpoint = scope.checkpoint;
    context.round = round;
    context.sequence = exchange_sequence_++;
    context.message_kind = message_kind;
    return context;
}

F ReferenceShamirResidualMpcBackend::DeriveCoefficient(
    const Digest& challenge, const OperationRef& ref,
    size_t coordinate, const Digest& domain_binding) const {
    std::vector<u64> words = {
        REFERENCE_RESIDUAL_BATCH_DOMAIN,
        active_sid_, active_checkpoint_,
        ref.owner, ref.object_id, static_cast<u64>(coordinate)
    };
    append_digest(challenge, &words);
    append_digest(domain_binding, &words);
    return digest_to_field(hash_words(words));
}

bool ReferenceShamirResidualMpcBackend::BuildFingerprint(
    const ObligationSet& scope,
    const std::vector<OperationRef>& operations,
    const Digest& challenge,
    const Digest& domain_binding,
    F* fingerprint_share,
    Digest* sharing_binding,
    ReferenceLinearSharingProvenance* provenance) const {
    if (!fingerprint_share || !sharing_binding || operations.empty() ||
        challenge == Digest{} || domain_binding == Digest{})
        return false;
    const bool activated = HasActivatedVssProvenance(scope);
    if (provenance) *provenance = ReferenceLinearSharingProvenance{};
    if (provenance && !activated) return false;

    *fingerprint_share = F(0);
    std::vector<Digest> operation_bindings;
    std::vector<ReferenceLinearSharingSource> provenance_sources;
    std::vector<OperationRef> ordered = operations;
    std::sort(ordered.begin(), ordered.end(), operation_less);
    if (provenance) provenance_sources.reserve(ordered.size());
    for (const OperationRef& ref : ordered) {
        if (ref.owner >= static_cast<uint32_t>(mpc_.world_size())) return false;
        std::vector<F> local_shares;
        const ActivatedResidualOperation* activated_operation = nullptr;
        if (activated) {
            activated_operation = FindActivated(ref);
            if (!activated_operation || activated_operation->local_shares.empty() ||
                activated_operation->descriptor_binding == Digest{} ||
                activated_operation->sharing_binding == Digest{})
                return false;
            local_shares = activated_operation->local_shares;
        } else {
            std::vector<F> plaintext;
            if (mpc_.rank() == static_cast<int>(ref.owner)) {
                const PrivateResidualShare* share = store_.Find(ref);
                if (share && validate_private_residual_share(*share) &&
                    share->authenticated && share->checkpoint == scope.checkpoint &&
                    share->ref == ref)
                    plaintext = share->values;
            }
            if (!mpc_.ShareVectorFromDealer(
                    static_cast<int>(ref.owner), plaintext, &local_shares) ||
                local_shares.empty())
                return false;
        }
        F local_operation_fingerprint(0);
        std::vector<F> coefficients;
        if (provenance) coefficients.reserve(local_shares.size());
        for (size_t coordinate = 0; coordinate < local_shares.size(); ++coordinate) {
            const F coefficient = DeriveCoefficient(
                challenge, ref, coordinate, domain_binding);
            local_operation_fingerprint += coefficient * local_shares[coordinate];
            if (provenance) coefficients.push_back(coefficient);
        }
        *fingerprint_share += local_operation_fingerprint;
        std::vector<u64> bind = {
            ref.owner, ref.object_id, static_cast<u64>(local_shares.size())};
        append_digest(challenge, &bind);
        append_digest(domain_binding, &bind);
        if (activated) {
            bind.push_back(1ULL);
            append_digest(activated_operation->descriptor_binding, &bind);
            append_digest(activated_operation->sharing_binding, &bind);
            append_digest(activation_binding_, &bind);
        }
        operation_bindings.push_back(hash_words(bind));
        if (provenance) {
            ReferenceLinearSharingSource source;
            source.sharing_binding = activated_operation->sharing_binding;
            source.element_coefficients = std::move(coefficients);
            source.local_witness = activated_operation->local_witness;
            provenance_sources.push_back(std::move(source));
        }
    }

    if (activated) operation_bindings.push_back(activation_binding_);
    *sharing_binding = bind_words(
        REFERENCE_RESIDUAL_BATCH_DOMAIN, operation_bindings,
        {static_cast<u64>(ordered.size()), activated ? 1ULL : 0ULL});
    if (*sharing_binding == Digest{}) return false;
    if (provenance &&
        (!build_reference_linear_sharing_provenance(
             std::move(provenance_sources), provenance) ||
         provenance->local_share != *fingerprint_share ||
         provenance->binding == Digest{}))
        return false;
    return true;
}

CollectiveResidualCommitmentSet
ReferenceShamirResidualMpcBackend::CommitResidualBatch(
    const ObligationSet& scope,
    const CollectiveBatchDescriptor& local_descriptor,
    const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    CollectiveResidualCommitmentSet out;
    out.checkpoint = scope.checkpoint;
    if (!EnsureTransport(scope, rank, world_size))
        return out;
    const bool local_ready =
        (HasActivatedResiduals(scope)
            ? ValidateActivatedLocalView(local_view, rank)
            : ValidateLocalView(local_view, rank)) &&
        local_descriptor.local_owner == static_cast<uint32_t>(rank) &&
        local_descriptor.world_size == world_size &&
        local_descriptor.descriptor_digest != Digest{} &&
        local_descriptor.local_commitment_root != Digest{};
    bool all_ready = false;
    Digest ready_binding{};
    if (!exchange_.AllTrue(
            NextContext(scope, AUTH_KIND_COMMIT_READY),
            local_ready, &all_ready, &ready_binding) ||
        !all_ready || ready_binding == Digest{})
        return out;

    std::vector<u64> local_payload = {
        static_cast<u64>(rank),
        static_cast<u64>(local_descriptor.local_handle_count)
    };
    append_digest(local_descriptor.descriptor_digest, &local_payload);
    append_digest(local_descriptor.local_commitment_root, &local_payload);
    std::vector<u64> gathered;
    Digest gather_binding{};
    if (!exchange_.AllGatherWords(
            NextContext(scope, AUTH_KIND_COMMITMENTS),
            local_payload, &gathered, &gather_binding) ||
        gather_binding == Digest{} ||
        gathered.size() != static_cast<size_t>(world_size) * local_payload.size())
        return out;

    const size_t stride = local_payload.size();
    out.participants.reserve(static_cast<size_t>(world_size));
    const Digest transport_capability = exchange_.ProductionCapabilityBinding();
    for (int i = 0; i < world_size; ++i) {
        const size_t offset = static_cast<size_t>(i) * stride;
        if (gathered[offset] != static_cast<u64>(i))
            return CollectiveResidualCommitmentSet{};
        ParticipantResidualCommitment participant;
        participant.owner = static_cast<uint32_t>(i);
        participant.handle_count = static_cast<size_t>(gathered[offset + 1]);
        participant.descriptor_digest = digest_from_words(gathered, offset + 2);
        participant.local_commitment_root = digest_from_words(gathered, offset + 6);
        participant.authentication_commitment = bind_words(
            REFERENCE_RESIDUAL_COMMIT_DOMAIN,
            {participant.descriptor_digest, participant.local_commitment_root,
             gather_binding, transport_capability},
            {participant.owner, static_cast<u64>(participant.handle_count)});
        if (participant.descriptor_digest == Digest{} ||
            participant.local_commitment_root == Digest{} ||
            participant.authentication_commitment == Digest{})
            return CollectiveResidualCommitmentSet{};
        out.participants.push_back(participant);
    }
    out.available = true;
    out.cryptographically_authenticated = true;
    out.root = compute_collective_residual_commitment_root(
        out.participants, out.security_attestation_binding);
    if (!validate_participant_commitment_set(
            scope, local_descriptor, out, world_size))
        return CollectiveResidualCommitmentSet{};
    return out;
}

AuthenticatedChallengeTranscript
ReferenceShamirResidualMpcBackend::DeriveJointChallenge(
    const ObligationSet& scope,
    const CollectiveBatchDescriptor& local_descriptor,
    const CollectiveResidualCommitmentSet& commitments,
    int rank, int world_size) const {
    AuthenticatedChallengeTranscript out;
    out.checkpoint = scope.checkpoint;
    if (!EnsureTransport(scope, rank, world_size))
        return out;
    const bool local_ready = validate_participant_commitment_set(
        scope, local_descriptor, commitments, world_size);
    bool all_ready = false;
    Digest ready_binding{};
    if (!exchange_.AllTrue(
            NextContext(scope, AUTH_KIND_CHALLENGE_READY),
            local_ready, &all_ready, &ready_binding) ||
        !all_ready || ready_binding == Digest{})
        return out;

    Digest seed{};
    Digest coin_transcript{};
    if (!mpc_.JointPublicSeed(&seed, &coin_transcript) ||
        seed == Digest{} || coin_transcript == Digest{})
        return out;
    out.available = true;
    out.cryptographically_authenticated = true;
    out.participant_count = commitments.participants.size();
    out.scope_binding = compute_collective_scope_binding(scope);
    out.participant_commitment_root = commitments.root;
    out.randomness_commitment = bind_words(
        REFERENCE_RESIDUAL_CHALLENGE_DOMAIN,
        {coin_transcript, commitments.root, out.scope_binding});
    out.challenge = bind_words(
        REFERENCE_RESIDUAL_CHALLENGE_DOMAIN,
        {seed, coin_transcript, commitments.root, out.scope_binding});
    out.security_attestation_binding =
        commitments.security_attestation_binding;
    out.proof_commitment = bind_words(
        REFERENCE_RESIDUAL_CHALLENGE_DOMAIN,
        {coin_transcript, exchange_.ProductionCapabilityBinding(),
         Capabilities().capability_binding});
    out.transcript_digest = compute_challenge_transcript_digest(out);
    if (!validate_challenge_transcript(
            scope, commitments, out, world_size))
        return AuthenticatedChallengeTranscript{};
    return out;
}

BatchCheckResult
ReferenceShamirResidualMpcBackend::RandomLinearBatchCheck(
    const ObligationSet& scope,
    const CollectiveBatchDescriptor& local_descriptor,
    const LocalResidualBatchView& local_view,
    const CollectiveResidualCommitmentSet& commitments,
    const AuthenticatedChallengeTranscript& challenge_transcript,
    int rank, int world_size) const {
    BatchCheckResult out;
    out.available = false;
    out.cryptographically_authenticated = false;
    out.ok = false;
    out.checkpoint = scope.checkpoint;
    if (!EnsureTransport(scope, rank, world_size)) return out;
    const bool activated = HasActivatedVssProvenance(scope);
    const bool local_ready =
        (activated ? ValidateActivatedLocalView(local_view, rank)
                   : ValidateLocalView(local_view, rank)) &&
        validate_participant_commitment_set(
            scope, local_descriptor, commitments, world_size) &&
        validate_challenge_transcript(
            scope, commitments, challenge_transcript, world_size);
    bool all_ready = false;
    Digest ready_binding{};
    if (!exchange_.AllTrue(
            NextContext(scope, AUTH_KIND_BATCH_READY), local_ready,
            &all_ready, &ready_binding) || !all_ready || ready_binding == Digest{})
        return out;

    const bool strong_zero = activated &&
        mpc_.multiplication_consistency_available();
    F fingerprint(0);
    Digest sharing_binding{};
    ReferenceLinearSharingProvenance provenance;
    if (!BuildFingerprint(
            scope, scope.operations, challenge_transcript.challenge,
            challenge_transcript.transcript_digest,
            &fingerprint, &sharing_binding,
            strong_zero ? &provenance : nullptr))
        return out;
    bool is_zero = false;
    Digest zero_binding{};
    Digest multiplication_binding{};
    if (strong_zero) {
        ReferenceMaskedZeroConsistencyContext context;
        context.sid = scope.session_id;
        context.checkpoint = scope.checkpoint;
        context.context_binding = bind_words(
            REFERENCE_RESIDUAL_STRONG_ZERO_DOMAIN,
            {sharing_binding, challenge_transcript.transcript_digest,
             activation_binding_},
            {0ULL, static_cast<u64>(scope.operations.size())});
        context.multiplication_id = nonzero_digest_word(context.context_binding);
        if (context.context_binding == Digest{} ||
            !mpc_.MaskedZeroTestWithConsistency(
                provenance, context, &is_zero, &zero_binding,
                &multiplication_binding) ||
            zero_binding == Digest{} || multiplication_binding == Digest{})
            return out;
    } else if (!mpc_.MaskedZeroTest(
                   fingerprint, &is_zero, &zero_binding) ||
               zero_binding == Digest{}) {
        return out;
    }

    out.available = true;
    out.cryptographically_authenticated = true;
    out.ok = is_zero;
    out.checked_operations = scope.operations.size();
    out.mismatches = is_zero ? 0 : 1;
    out.participant_count = commitments.participants.size();
    out.scope_binding = compute_collective_scope_binding(scope);
    out.participant_commitment_root = commitments.root;
    out.challenge_transcript_binding = challenge_transcript.transcript_digest;
    out.challenge = challenge_transcript.challenge;
    out.security_attestation_binding =
        challenge_transcript.security_attestation_binding;
    std::vector<Digest> audit_bindings = {
        sharing_binding, zero_binding, commitments.root,
        challenge_transcript.transcript_digest};
    if (strong_zero) audit_bindings.push_back(multiplication_binding);
    out.aggregate_residual_commitment = bind_words(
        REFERENCE_RESIDUAL_BATCH_DOMAIN, audit_bindings,
        {is_zero ? 1ULL : 0ULL,
         static_cast<u64>(scope.operations.size()),
         strong_zero ? 1ULL : 0ULL});
    if (!validate_collective_batch_result(scope, out, world_size))
        return BatchCheckResult{};
    return out;
}

ResidualSubsetCheckResult
ReferenceShamirResidualMpcBackend::CheckResidualSubset(
    const ObligationSet& scope,
    const BatchCheckResult& batch,
    const ResidualSubsetDescriptor& subset,
    const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    ResidualSubsetCheckResult out;
    out.checkpoint = scope.checkpoint;
    if (!EnsureTransport(scope, rank, world_size)) return out;
    const bool activated = HasActivatedVssProvenance(scope);
    const bool local_ready =
        (activated ? ValidateActivatedLocalView(local_view, rank)
                   : ValidateLocalView(local_view, rank)) &&
        validate_collective_batch_result(scope, batch, world_size) &&
        !batch.ok && !subset.operations.empty() &&
        subset.checkpoint == batch.checkpoint &&
        subset.batch_result_binding == compute_collective_batch_result_binding(batch) &&
        subset.challenge_transcript_binding == batch.challenge_transcript_binding &&
        subset.binding != Digest{};
    bool all_ready = false;
    Digest ready_binding{};
    if (!exchange_.AllTrue(
            NextContext(scope, AUTH_KIND_SUBSET_READY, subset.depth), local_ready,
            &all_ready, &ready_binding) || !all_ready || ready_binding == Digest{})
        return out;
    const bool strong_zero = activated &&
        mpc_.multiplication_consistency_available();
    F fingerprint(0);
    Digest sharing_binding{};
    ReferenceLinearSharingProvenance provenance;
    if (!BuildFingerprint(
            scope, subset.operations, batch.challenge, subset.binding,
            &fingerprint, &sharing_binding,
            strong_zero ? &provenance : nullptr))
        return out;
    bool is_zero = false;
    Digest zero_binding{};
    Digest multiplication_binding{};
    if (strong_zero) {
        ReferenceMaskedZeroConsistencyContext context;
        context.sid = scope.session_id;
        context.checkpoint = scope.checkpoint;
        context.context_binding = bind_words(
            REFERENCE_RESIDUAL_STRONG_ZERO_DOMAIN,
            {sharing_binding, subset.binding, activation_binding_},
            {1ULL, subset.depth, static_cast<u64>(subset.operations.size())});
        context.multiplication_id = nonzero_digest_word(context.context_binding);
        if (context.context_binding == Digest{} ||
            !mpc_.MaskedZeroTestWithConsistency(
                provenance, context, &is_zero, &zero_binding,
                &multiplication_binding) ||
            zero_binding == Digest{} || multiplication_binding == Digest{})
            return out;
    } else if (!mpc_.MaskedZeroTest(
                   fingerprint, &is_zero, &zero_binding) ||
               zero_binding == Digest{}) {
        return out;
    }

    out.available = true;
    out.cryptographically_authenticated = true;
    out.failed = !is_zero;
    out.batch_result_binding = subset.batch_result_binding;
    out.challenge_transcript_binding = subset.challenge_transcript_binding;
    out.security_attestation_binding = subset.security_attestation_binding;
    out.subset_binding = subset.binding;
    std::vector<Digest> proof_bindings = {
        subset.binding, sharing_binding, zero_binding,
        batch.challenge_transcript_binding};
    if (strong_zero) proof_bindings.push_back(multiplication_binding);
    out.proof_commitment = bind_words(
        REFERENCE_RESIDUAL_SUBSET_DOMAIN, proof_bindings,
        {subset.depth, is_zero ? 1ULL : 0ULL,
         static_cast<u64>(subset.operations.size()),
         strong_zero ? 1ULL : 0ULL});
    if (!validate_residual_subset_check(batch, subset, out))
        return ResidualSubsetCheckResult{};
    return out;
}

CollectiveDisputeResult
ReferenceShamirResidualMpcBackend::FinalizeLocalization(
    const ObligationSet& scope,
    const BatchCheckResult& batch,
    const OperationRef& accused,
    const Digest& recursive_transcript_binding,
    const LocalResidualBatchView& local_view,
    int rank, int world_size) const {
    CollectiveDisputeResult out;
    out.checkpoint = scope.checkpoint;
    if (!EnsureTransport(scope, rank, world_size))
        return out;
    const bool activated = HasActivatedResiduals(scope);
    const bool local_ready =
        (activated
            ? ValidateActivatedLocalView(local_view, rank)
            : ValidateLocalView(local_view, rank)) &&
        validate_collective_batch_result(scope, batch, world_size) &&
        !batch.ok && recursive_transcript_binding != Digest{} &&
        accused.owner < static_cast<uint32_t>(world_size);
    bool all_ready = false;
    Digest ready_binding{};
    if (!exchange_.AllTrue(
            NextContext(scope, AUTH_KIND_LOCALIZE_READY, accused.object_id),
            local_ready, &all_ready, &ready_binding) ||
        !all_ready || ready_binding == Digest{})
        return out;

    Digest localization_source_binding{};
    Digest private_share_commitment{};
    if (activated) {
        const ActivatedResidualOperation* operation = FindActivated(accused);
        if (!operation || operation->expected == Digest{} ||
            operation->actual == Digest{} ||
            operation->expected == operation->actual ||
            operation->operation_statement_binding == Digest{} ||
            operation->source_commitment == Digest{} ||
            operation->descriptor_binding == Digest{})
            return out;

        out.available = true;
        out.cryptographically_authenticated = true;
        out.found = true;
        out.accused = accused;
        out.relation = operation->relation;
        out.kernel = operation->kernel;
        out.label = operation->label;
        out.expected = operation->expected;
        out.actual = operation->actual;
        out.operation_statement_binding =
            operation->operation_statement_binding;
        private_share_commitment = operation->source_commitment;
        localization_source_binding = bind_words(
            REFERENCE_RESIDUAL_LOCALIZE_DOMAIN,
            {activation_binding_, operation->descriptor_binding,
             operation->source_commitment, ready_binding},
            {accused.owner, accused.object_id, 1ULL});
        if (localization_source_binding == Digest{}) return out;
    } else {
        std::vector<u64> payload;
        if (rank == static_cast<int>(accused.owner)) {
            payload.assign(25, 0ULL);
            const PrivateResidualShare* share = store_.Find(accused);
            const PrivateResidualHandle* handle = find_handle(local_view, accused);
            const bool descriptor_ready =
                share && handle && validate_private_residual_share(*share) &&
                share->authenticated && share->commitment == handle->commitment &&
                share->expected != Digest{} && share->actual != Digest{} &&
                share->expected != share->actual &&
                share->operation_statement_binding != Digest{};
            if (descriptor_ready) {
                payload[0] = 1ULL;
                payload[1] = static_cast<u64>(share->relation);
                payload[2] = static_cast<u64>(share->kernel);
                payload[3] = share->label.sid;
                payload[4] = static_cast<u64>(share->label.phase);
                payload[5] = share->label.round;
                payload[6] = share->label.owner;
                payload[7] = static_cast<u64>(share->label.obligation);
                payload[8] = share->label.object_id;
                auto put_digest = [&](size_t offset, const Digest& digest) {
                    for (size_t i = 0; i < 4; ++i)
                        std::memcpy(&payload[offset + i],
                                    digest.bytes.data() + 8 * i, 8);
                };
                put_digest(9, share->expected);
                put_digest(13, share->actual);
                put_digest(17, share->operation_statement_binding);
                put_digest(21, share->commitment);
            }
        }

        std::vector<u64> received;
        if (!exchange_.BroadcastWords(
                NextContext(scope, AUTH_KIND_LOCALIZATION, accused.object_id),
                static_cast<int>(accused.owner), payload, &received,
                &localization_source_binding) ||
            received.size() != 25 || received[0] != 1ULL ||
            localization_source_binding == Digest{})
            return out;

        out.available = true;
        out.cryptographically_authenticated = true;
        out.found = true;
        out.accused = accused;
        out.relation = static_cast<RelationKind>(received[1]);
        out.kernel = static_cast<AuditRelationKernel>(received[2]);
        out.label.sid = received[3];
        out.label.phase = static_cast<Phase>(received[4]);
        out.label.round = static_cast<uint32_t>(received[5]);
        out.label.owner = static_cast<uint32_t>(received[6]);
        out.label.obligation = static_cast<Obligation>(received[7]);
        out.label.object_id = received[8];
        out.expected = digest_from_words(received, 9);
        out.actual = digest_from_words(received, 13);
        out.operation_statement_binding = digest_from_words(received, 17);
        private_share_commitment = digest_from_words(received, 21);
    }

    if (out.label.owner != accused.owner ||
        out.label.object_id != accused.object_id ||
        out.label.sid != scope.session_id ||
        out.label.phase != scope.phase ||
        (scope.exact_round && out.label.round != scope.round) ||
        out.expected == Digest{} || out.actual == Digest{} ||
        out.expected == out.actual ||
        out.operation_statement_binding == Digest{} ||
        private_share_commitment == Digest{})
        return CollectiveDisputeResult{};

    out.residual_commitment = compute_residual_commitment(
        out.label, out.relation, out.kernel, out.expected, out.actual);
    out.batch_result_binding = compute_collective_batch_result_binding(batch);
    out.public_evidence_binding = Digest{};
    out.security_attestation_binding = batch.security_attestation_binding;
    out.recursive_transcript_binding = recursive_transcript_binding;
    if (activated) {
        out.localization_commitment = bind_words(
            REFERENCE_RESIDUAL_LOCALIZE_DOMAIN,
            {out.batch_result_binding, recursive_transcript_binding,
             ready_binding, localization_source_binding,
             private_share_commitment, out.residual_commitment,
             out.operation_statement_binding, activation_binding_},
            {1ULL});
    } else {
        out.localization_commitment = bind_words(
            REFERENCE_RESIDUAL_LOCALIZE_DOMAIN,
            {out.batch_result_binding, recursive_transcript_binding,
             ready_binding, localization_source_binding,
             private_share_commitment, out.residual_commitment,
             out.operation_statement_binding});
    }
    if (!validate_collective_dispute_result(scope, batch, out))
        return CollectiveDisputeResult{};
    return out;
}

} // namespace pvia
