#include "FoldResidualRuntimeHarness.hpp"

#include <mpi.h>

#include <algorithm>
#include <cstring>
#include <iostream>

namespace pvia {
namespace {

constexpr int LIVE_FOLD_DESCRIPTOR_WORDS = 21;

struct LiveFoldDescriptor {
    u64 sid = 0;
    u64 checkpoint = 0;
    u64 owner = 0;
    u64 object_id = 0;
    u64 state_id = 0;
    u64 challenge_real = 0;
    u64 challenge_img = 0;
    u64 state_size = 0;
    u64 output_size = 0;
    Digest state_digest{};
    Digest actual_digest{};
    Digest statement_binding{};
};

void append_live_digest(const Digest& digest, std::vector<u64>* words) {
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

Digest read_live_digest(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}

} // namespace


FoldResidualRuntimeHarness::FoldResidualRuntimeHarness(
    bool enable_reference_mpc_activation)
    : backend_(shares_),
      reference_mpc_activation_enabled_(enable_reference_mpc_activation) {}

void FoldResidualRuntimeHarness::OnImportStateMetadata(
    const AuditStateView& state) {
    states_.RegisterMetadata(state);
}

void FoldResidualRuntimeHarness::OnBindPrivateState(
    const AuditStateView& state, const std::vector<F>& local_share) {
    states_.BindPrivateState(state, local_share);
}

void FoldResidualRuntimeHarness::OnRegisterOperation(
    const AuditOperationView& operation) {
    materials_.RegisterOperation(operation);
}

void FoldResidualRuntimeHarness::OnActivateOperation(
    const AuditOperationView& operation) {
    materials_.ActivateOperation(operation);
}
void FoldResidualRuntimeHarness::OnBindPrivateFieldOperation(
    const AuditOperationView& operation, AuditPrivatePayloadKind kind,
    AuditPayloadStage stage, const std::vector<F>& values) {
    materials_.BindPrivateField(operation, kind, stage, values);
}

void FoldResidualRuntimeHarness::OnBindOperationStateDependencies(
    const AuditOperationView& operation,
    const std::vector<StateId>& state_ids) {
    materials_.BindStateDependencies(operation, state_ids);
}

void FoldResidualRuntimeHarness::OnBindPublicFieldAux(
    const AuditOperationView& operation, AuditPublicAuxKind kind,
    const std::vector<F>& values) {
    materials_.BindPublicFieldAux(operation, kind, values);
}

void FoldResidualRuntimeHarness::OnFinalizePrivateRelation(
    const AuditOperationView& operation) {
    if (operation.kernel != AuditRelationKernel::FOLD_RS) return;
    ++fold_operations_;
    const PrivateOperationMaterial* material = materials_.Find(operation.ref);
    if (!material || !materials_.ReadyForResidual(operation.ref)) {
        ++invalid_material_;
        return;
    }
    for (StateId state_id : material->state_dependencies) {
        if (!states_.VerifyDigest(state_id)) {
            ++invalid_material_;
            return;
        }
    }
    KernelResidualContext context{operation, *material, states_};
    const PrivateResidualHandle handle = backend_.EvaluateKernel(context);
    const PrivateResidualShare* share = shares_.Find(operation.ref);
    if (!handle.available || handle.authenticated || !share ||
        !validate_private_residual_share(*share) || share->authenticated) {
        ++invalid_material_;
        return;
    }
    bool zero = true;
    for (const F& value : share->values) {
        if (value != F(0)) {
            zero = false;
            break;
        }
    }
    if (zero) ++zero_residuals_;
    else ++nonzero_residuals_;
    materials_.MarkFinalized(operation.ref);
    if (std::find(fold_refs_.begin(), fold_refs_.end(), operation.ref) ==
        fold_refs_.end())
        fold_refs_.push_back(operation.ref);
}

void FoldResidualRuntimeHarness::OnSealCheckpoint(
    const AuditCheckpointView& checkpoint) {
    if (!reference_mpc_activation_enabled_ || !checkpoint.sealed ||
        checkpoint.phase != Phase::FOLD)
        return;
    int rank = -1;
    int world_size = 0;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);
    if (!ActivateReferenceMpcCheckpoint(checkpoint, rank, world_size))
        ++reference_mpc_activation_failures_;
}

bool FoldResidualRuntimeHarness::ActivateReferenceMpcCheckpoint(
    const AuditCheckpointView& checkpoint, int rank, int world_size) {
    if (world_size < 3 || rank < 0 || rank >= world_size ||
        checkpoint.id == 0 || !checkpoint.sealed ||
        checkpoint.phase != Phase::FOLD)
        return false;
    const int threshold = (world_size - 1) / 2;
    if (2 * threshold >= world_size) return false;

    u64 local_header[4] = {
        checkpoint.id,
        static_cast<u64>(checkpoint.phase),
        checkpoint.round,
        checkpoint.sealed ? 1ULL : 0ULL};
    std::vector<u64> all_headers(static_cast<size_t>(world_size) * 4);
    MPI_Allgather(local_header, 4, MPI_UINT64_T,
                  all_headers.data(), 4, MPI_UINT64_T, MPI_COMM_WORLD);
    for (int participant = 0; participant < world_size; ++participant) {
        const size_t off = static_cast<size_t>(participant) * 4;
        if (all_headers[off] != local_header[0] ||
            all_headers[off + 1] != local_header[1] ||
            all_headers[off + 2] != local_header[2] ||
            all_headers[off + 3] != 1ULL)
            return false;
    }

    std::vector<LiveFoldDescriptor> local_descriptors;
    int local_invalid = 0;
    for (const OperationRef& ref : checkpoint.operations) {
        const PrivateOperationMaterial* material = materials_.Find(ref);
        if (!material || material->operation.kernel != AuditRelationKernel::FOLD_RS)
            continue;
        if (material->operation.ref.owner != static_cast<uint32_t>(rank))
            continue;
        if (!material->finalized || material->state_dependencies.size() != 1 ||
            !material->has_field_output ||
            !materials_.ReadyForResidual(ref)) {
            ++local_invalid;
            continue;
        }
        const StateId state_id = material->state_dependencies.front();
        const PrivateStateMaterial* state = states_.Find(state_id);
        KernelResidualContext context{material->operation, *material, states_};
        const std::vector<F>* challenge =
            context.field_aux(AuditPublicAuxKind::FOLD_CHALLENGE);
        if (!state || !state->has_private_share ||
            !states_.VerifyDigest(state_id) || !challenge ||
            challenge->size() != 1 ||
            !validate_kernel_residual_material(context) ||
            material->operation.actual == Digest{} ||
            material->operation.relation_statement == Digest{}) {
            ++local_invalid;
            continue;
        }
        LiveFoldDescriptor descriptor;
        descriptor.sid = material->operation.label.sid;
        descriptor.checkpoint = material->operation.checkpoint;
        descriptor.owner = material->operation.ref.owner;
        descriptor.object_id = material->operation.ref.object_id;
        descriptor.state_id = state_id;
        descriptor.challenge_real = challenge->front().real;
        descriptor.challenge_img = challenge->front().img;
        descriptor.state_size = state->local_share.size();
        descriptor.output_size = material->field_output.size();
        descriptor.state_digest = state->state.digest;
        descriptor.actual_digest = material->operation.actual;
        descriptor.statement_binding = material->operation.relation_statement;
        local_descriptors.push_back(descriptor);
    }
    int global_invalid = 0;
    MPI_Allreduce(&local_invalid, &global_invalid, 1, MPI_INT, MPI_SUM,
                  MPI_COMM_WORLD);
    if (global_invalid != 0) return false;

    std::vector<u64> local_words;
    local_words.reserve(local_descriptors.size() * LIVE_FOLD_DESCRIPTOR_WORDS);
    for (const LiveFoldDescriptor& d : local_descriptors) {
        local_words.insert(local_words.end(), {
            d.sid, d.checkpoint, d.owner, d.object_id, d.state_id,
            d.challenge_real, d.challenge_img, d.state_size, d.output_size});
        append_live_digest(d.state_digest, &local_words);
        append_live_digest(d.actual_digest, &local_words);
        append_live_digest(d.statement_binding, &local_words);
    }
    const int local_word_count = static_cast<int>(local_words.size());
    std::vector<int> word_counts(static_cast<size_t>(world_size), 0);
    MPI_Allgather(&local_word_count, 1, MPI_INT,
                  word_counts.data(), 1, MPI_INT, MPI_COMM_WORLD);
    std::vector<int> displacements(static_cast<size_t>(world_size), 0);
    int total_words = 0;
    for (int i = 0; i < world_size; ++i) {
        if (word_counts[static_cast<size_t>(i)] < 0 ||
            word_counts[static_cast<size_t>(i)] % LIVE_FOLD_DESCRIPTOR_WORDS != 0)
            return false;
        displacements[static_cast<size_t>(i)] = total_words;
        total_words += word_counts[static_cast<size_t>(i)];
    }
    std::vector<u64> all_words(static_cast<size_t>(total_words));
    MPI_Allgatherv(local_words.empty() ? nullptr : local_words.data(),
                   local_word_count, MPI_UINT64_T,
                   all_words.empty() ? nullptr : all_words.data(),
                   word_counts.data(), displacements.data(), MPI_UINT64_T,
                   MPI_COMM_WORLD);
    if (all_words.empty()) return true;

    std::vector<LiveFoldDescriptor> descriptors;
    descriptors.reserve(all_words.size() / LIVE_FOLD_DESCRIPTOR_WORDS);
    for (size_t off = 0; off < all_words.size();
         off += LIVE_FOLD_DESCRIPTOR_WORDS) {
        LiveFoldDescriptor d;
        d.sid = all_words[off + 0];
        d.checkpoint = all_words[off + 1];
        d.owner = all_words[off + 2];
        d.object_id = all_words[off + 3];
        d.state_id = all_words[off + 4];
        d.challenge_real = all_words[off + 5];
        d.challenge_img = all_words[off + 6];
        d.state_size = all_words[off + 7];
        d.output_size = all_words[off + 8];
        d.state_digest = read_live_digest(all_words, off + 9);
        d.actual_digest = read_live_digest(all_words, off + 13);
        d.statement_binding = read_live_digest(all_words, off + 17);
        descriptors.push_back(d);
    }
    std::sort(descriptors.begin(), descriptors.end(),
        [](const LiveFoldDescriptor& lhs, const LiveFoldDescriptor& rhs) {
            if (lhs.owner != rhs.owner) return lhs.owner < rhs.owner;
            return lhs.object_id < rhs.object_id;
        });
    const u64 sid = descriptors.front().sid;
    if (sid == 0) return false;
    for (size_t i = 0; i < descriptors.size(); ++i) {
        const LiveFoldDescriptor& d = descriptors[i];
        if (d.sid != sid || d.checkpoint != checkpoint.id ||
            d.owner >= static_cast<u64>(world_size) ||
            d.state_size == 0 || d.output_size == 0 ||
            d.state_digest == Digest{} || d.actual_digest == Digest{} ||
            d.statement_binding == Digest{})
            return false;
        if (i > 0 && descriptors[i - 1].owner == d.owner &&
            descriptors[i - 1].object_id == d.object_id)
            return false;
    }

    auto session = std::make_unique<ReferenceShamirAuditSession>(
        sid, checkpoint.id, rank, world_size, threshold);
    for (const LiveFoldDescriptor& d : descriptors) {
        const OperationRef ref{static_cast<uint32_t>(d.owner), d.object_id};
        const F challenge(static_cast<long long>(d.challenge_real),
                          static_cast<long long>(d.challenge_img));
        std::vector<F> owner_state;
        std::vector<F> owner_output;
        int local_ready = 1;
        if (rank == static_cast<int>(d.owner)) {
            const PrivateOperationMaterial* material = materials_.Find(ref);
            const PrivateStateMaterial* state = states_.Find(d.state_id);
            if (!material || !state || !state->has_private_share ||
                material->state_dependencies.size() != 1 ||
                material->state_dependencies.front() != d.state_id ||
                state->local_share.size() != d.state_size ||
                material->field_output.size() != d.output_size ||
                state->state.digest != d.state_digest ||
                material->operation.actual != d.actual_digest ||
                material->operation.relation_statement != d.statement_binding) {
                local_ready = 0;
            } else {
                KernelResidualContext context{
                    material->operation, *material, states_};
                const std::vector<F>* local_challenge =
                    context.field_aux(AuditPublicAuxKind::FOLD_CHALLENGE);
                if (!local_challenge || local_challenge->size() != 1 ||
                    local_challenge->front() != challenge) {
                    local_ready = 0;
                } else {
                    owner_state = state->local_share;
                    owner_output = material->field_output;
                }
            }
        }
        int global_ready = 0;
        MPI_Allreduce(&local_ready, &global_ready, 1, MPI_INT, MPI_MIN,
                      MPI_COMM_WORLD);
        if (!global_ready) return false;
        if (!session->RegisterFoldOperation(
                static_cast<uint32_t>(d.owner), ref, challenge,
                d.state_digest, d.actual_digest, d.statement_binding,
                owner_state, owner_output))
            return false;
    }
    if (!session->SealRegistration()) return false;
    const ReferenceShamirBatchResult batch = session->BatchCheck();
    if (!batch.available || batch.checkpoint != checkpoint.id ||
        batch.operation_count != descriptors.size())
        return false;
    reference_mpc_batches_.push_back(batch);
    reference_mpc_sessions_.push_back(std::move(session));
    return true;
}

bool FoldResidualRuntimeHarness::RunSelfCheck(
    int rank, int world_size) const {
    if (world_size <= 0 || rank < 0 || rank >= world_size) return false;
    unsigned long long local[4] = {
        static_cast<unsigned long long>(fold_operations_),
        static_cast<unsigned long long>(zero_residuals_),
        static_cast<unsigned long long>(nonzero_residuals_),
        static_cast<unsigned long long>(invalid_material_)};
    unsigned long long global[4] = {0, 0, 0, 0};
    MPI_Allreduce(local, global, 4, MPI_UNSIGNED_LONG_LONG, MPI_SUM,
                  MPI_COMM_WORLD);
    const bool ok = global[0] > 0 && global[0] == global[1] &&
        global[2] == 0 && global[3] == 0;
    if (rank == 0) {
        std::cout << "[PVIA][fold-runtime-selftest] operations=" << global[0]
                  << " zero=" << global[1]
                  << " nonzero=" << global[2]
                  << " invalid=" << global[3]
                  << " result=" << (ok ? "PASS" : "FAIL") << "\n";
    }
    return ok;
}

bool FoldResidualRuntimeHarness::RunReferenceMpcSelfCheck(
    int rank, int world_size) const {
    if (!reference_mpc_activation_enabled_ || world_size < 3 ||
        rank < 0 || rank >= world_size)
        return false;

    size_t operations = 0;
    size_t failed_sessions = 0;
    bool local_valid = reference_mpc_activation_failures_ == 0 &&
        !reference_mpc_sessions_.empty() &&
        reference_mpc_sessions_.size() == reference_mpc_batches_.size();
    for (size_t i = 0; i < reference_mpc_batches_.size(); ++i) {
        const ReferenceShamirBatchResult& batch = reference_mpc_batches_[i];
        const auto& session = reference_mpc_sessions_[i];
        if (!session || !session->sealed() || !batch.available ||
            batch.registration_binding != session->registration_binding() ||
            batch.operation_count != session->operation_count()) {
            local_valid = false;
            continue;
        }
        operations += batch.operation_count;
        if (!batch.clean) ++failed_sessions;
    }
    local_valid = local_valid && operations > 0 && failed_sessions == 0;
    int local_ok = local_valid ? 1 : 0;
    int global_ok = 0;
    MPI_Allreduce(&local_ok, &global_ok, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    if (rank == 0) {
        std::cout << "[PVIA][shamir-fold-runtime-selftest] sessions="
                  << reference_mpc_sessions_.size()
                  << " operations=" << operations
                  << " clean=" << (reference_mpc_batches_.size() - failed_sessions)
                  << " failed=" << failed_sessions
                  << " activation-errors=" << reference_mpc_activation_failures_
                  << " result=" << (global_ok ? "PASS" : "FAIL")
                  << "\n";
    }
    return global_ok != 0;
}

BatchCheckResult FoldResidualRuntimeHarness::BatchCheck(
    const ObligationSet& scope) const {
    BatchCheckResult out;
    out.checkpoint = scope.checkpoint;
    return out;
}

Violation FoldResidualRuntimeHarness::Dispute(
    const ObligationSet&, const BatchCheckResult&) const {
    return Violation{};
}

RecoverableAuditShare FoldResidualRuntimeHarness::RecoverAudit(
    const Violation&) const {
    return RecoverableAuditShare{};
}
BlameCertificate FoldResidualRuntimeHarness::LiftBlame(
    const Violation&, const RecoverableAuditShare&) const {
    return BlameCertificate{};
}

bool FoldResidualRuntimeHarness::Judge(
    const BlameCertificate&, uint64_t) const {
    return false;
}

} // namespace pvia
