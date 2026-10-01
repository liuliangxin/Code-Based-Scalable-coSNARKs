#include "InitialValidityGate.hpp"

#include "AuthenticatedMpcExchange.hpp"
#include "ReferenceShamirMpc.hpp"
#include "ProtocolTrafficMetrics.hpp"
#include "MultiplicationConsistencyBackendRegistry.hpp"
#include "../utils.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <iostream>
#include <limits>
#include <vector>

namespace pvia {
namespace {

constexpr u64 INITIAL_VALIDITY_COEFF_DOMAIN = 0x50564956414c4346ULL; // PVIVALCF
constexpr u64 INITIAL_VALIDITY_LINK_COEFF_DOMAIN = 0x505649564c4e4b43ULL; // PVIVLNKC
constexpr u64 INITIAL_VALIDITY_RELATION_PART_DOMAIN = 0x5056495652504152ULL; // PVIVRPAR
constexpr u64 INITIAL_VALIDITY_RELATION_BIND_DOMAIN = 0x505649565242494eULL; // PVIVRBIN
constexpr u64 INITIAL_VALIDITY_BIND_DOMAIN  = 0x50564956414c424eULL; // PVIVALBN

void append_digest_words(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

F digest_to_field(const Digest& digest) {
    u64 real = 0;
    u64 imag = 0;
    std::memcpy(&real, digest.bytes.data(), 8);
    std::memcpy(&imag, digest.bytes.data() + 8, 8);
    return F(static_cast<long long>(real % F::mod),
             static_cast<long long>(imag % F::mod));
}

bool exact_log2(int value, int* log_value) {
    if (!log_value || value <= 0 || (value & (value - 1)) != 0)
        return false;
    int out = 0;
    while ((1 << out) < value) ++out;
    *log_value = out;
    return true;
}

F coefficient_from_seed(
    const Digest& seed,
    uint64_t sid,
    int world_size,
    int k,
    int packed_width,
    size_t block,
    int slot) {
    std::vector<u64> words = {
        INITIAL_VALIDITY_COEFF_DOMAIN,
        sid,
        static_cast<u64>(world_size),
        static_cast<u64>(k),
        static_cast<u64>(packed_width),
        static_cast<u64>(block),
        static_cast<u64>(slot)};
    append_digest_words(seed, &words);
    return digest_to_field(hash_words(words));
}


F linkage_coefficient_from_seed(
    const Digest& seed,
    const Digest& relation_binding,
    uint64_t sid,
    int world_size,
    int k,
    int packed_width,
    int lane,
    size_t constraint) {
    std::vector<u64> words = {
        INITIAL_VALIDITY_LINK_COEFF_DOMAIN,
        sid,
        static_cast<u64>(world_size),
        static_cast<u64>(k),
        static_cast<u64>(packed_width),
        static_cast<u64>(lane),
        static_cast<u64>(constraint)};
    append_digest_words(seed, &words);
    append_digest_words(relation_binding, &words);
    return digest_to_field(hash_words(words));
}

Digest local_relation_partition_binding(
    const std::vector<std::vector<std::pair<int,int>>>& pA,
    const std::vector<std::vector<std::pair<int,int>>>& pB,
    const std::vector<std::vector<std::pair<int,int>>>& pC,
    int rank,
    int world_size,
    size_t witness_slots,
    size_t constraint_slots) {
    if (rank < 0 || world_size <= 0 ||
        witness_slots == 0 || witness_slots % static_cast<size_t>(world_size) != 0)
        return {};
    const size_t slice = witness_slots / static_cast<size_t>(world_size);
    if (pA.size() != slice || pB.size() != slice || pC.size() != slice)
        return {};
    const std::vector<const std::vector<std::vector<std::pair<int,int>>>*> lanes = {
        &pA, &pB, &pC};
    std::vector<u64> words = {
        INITIAL_VALIDITY_RELATION_PART_DOMAIN,
        static_cast<u64>(rank),
        static_cast<u64>(world_size),
        static_cast<u64>(witness_slots),
        static_cast<u64>(constraint_slots),
        static_cast<u64>(slice)};
    for (size_t lane = 0; lane < lanes.size(); ++lane) {
        words.push_back(static_cast<u64>(lane));
        const auto& rows = *lanes[lane];
        for (size_t local_wire = 0; local_wire < rows.size(); ++local_wire) {
            const size_t expected_wire =
                static_cast<size_t>(rank) * slice + local_wire;
            words.push_back(static_cast<u64>(expected_wire));
            words.push_back(static_cast<u64>(rows[local_wire].size()));
            for (const auto& entry : rows[local_wire]) {
                if (entry.first < 0 || entry.second < 0 ||
                    static_cast<size_t>(entry.first) != expected_wire ||
                    static_cast<size_t>(entry.second) >= constraint_slots)
                    return {};
                words.push_back(static_cast<u64>(entry.first));
                words.push_back(static_cast<u64>(entry.second));
            }
        }
    }
    return hash_words(words);
}

Digest collective_relation_binding(
    const Digest& local_binding,
    int world_size,
    MPI_Comm comm) {
    if (local_binding == Digest{} || world_size <= 0) return {};
    const size_t digest_bytes = local_binding.bytes.size();
    std::vector<uint8_t> gathered(
        static_cast<size_t>(world_size) * digest_bytes);
    MPI_Allgather(
        local_binding.bytes.data(), static_cast<int>(digest_bytes), MPI_BYTE,
        gathered.data(), static_cast<int>(digest_bytes), MPI_BYTE, comm);
    record_control_allgather(
        static_cast<uint64_t>(digest_bytes), world_size);
    std::vector<u64> words = {
        INITIAL_VALIDITY_RELATION_BIND_DOMAIN,
        static_cast<u64>(world_size)};
    for (int participant = 0; participant < world_size; ++participant) {
        Digest part{};
        std::memcpy(
            part.bytes.data(),
            gathered.data() + static_cast<size_t>(participant) * digest_bytes,
            digest_bytes);
        append_digest_words(part, &words);
    }
    return hash_words(words);
}

bool build_global_wire_coefficients(
    const Digest& seed,
    const Digest& relation_binding,
    uint64_t sid,
    int rank,
    int world_size,
    int k,
    int packed_width,
    size_t witness_slots,
    size_t constraint_slots,
    const std::vector<std::vector<std::pair<int,int>>>& pA,
    const std::vector<std::vector<std::pair<int,int>>>& pB,
    const std::vector<std::vector<std::pair<int,int>>>& pC,
    std::vector<F>* global_coefficients,
    MPI_Comm comm) {
    if (!global_coefficients || world_size <= 0 ||
        witness_slots == 0 ||
        witness_slots % static_cast<size_t>(world_size) != 0)
        return false;
    const size_t slice = witness_slots / static_cast<size_t>(world_size);
    if (pA.size() != slice || pB.size() != slice || pC.size() != slice)
        return false;
    const std::vector<const std::vector<std::vector<std::pair<int,int>>>*> lanes = {
        &pA, &pB, &pC};
    std::vector<F> local_coefficients(3 * slice, F(0));
    for (size_t lane = 0; lane < lanes.size(); ++lane) {
        const auto& rows = *lanes[lane];
        for (size_t local_wire = 0; local_wire < rows.size(); ++local_wire) {
            const size_t expected_wire =
                static_cast<size_t>(rank) * slice + local_wire;
            F coefficient(0);
            for (const auto& entry : rows[local_wire]) {
                if (entry.first < 0 || entry.second < 0 ||
                    static_cast<size_t>(entry.first) != expected_wire ||
                    static_cast<size_t>(entry.second) >= constraint_slots)
                    return false;
                coefficient += linkage_coefficient_from_seed(
                    seed, relation_binding, sid, world_size, k, packed_width,
                    static_cast<int>(lane),
                    static_cast<size_t>(entry.second));
            }
            local_coefficients[lane * slice + local_wire] = coefficient;
        }
    }

    if (local_coefficients.size() >
        static_cast<size_t>(std::numeric_limits<int>::max() / 2))
        return false;
    std::vector<u64> local_words(local_coefficients.size() * 2);
    for (size_t i = 0; i < local_coefficients.size(); ++i) {
        local_words[2*i] = local_coefficients[i].real;
        local_words[2*i+1] = local_coefficients[i].img;
    }
    std::vector<u64> gathered_words(
        local_words.size() * static_cast<size_t>(world_size), 0);
    MPI_Allgather(
        local_words.data(), static_cast<int>(local_words.size()), MPI_UINT64_T,
        gathered_words.data(), static_cast<int>(local_words.size()),
        MPI_UINT64_T, comm);
    record_control_allgather(
        static_cast<uint64_t>(local_words.size() * sizeof(u64)),
        world_size);

    global_coefficients->assign(3 * witness_slots, F(0));
    for (int participant = 0; participant < world_size; ++participant) {
        const size_t participant_base =
            static_cast<size_t>(participant) * local_words.size();
        for (size_t lane = 0; lane < 3; ++lane) {
            for (size_t local_wire = 0; local_wire < slice; ++local_wire) {
                const size_t src_field = lane * slice + local_wire;
                const size_t src_word = participant_base + 2 * src_field;
                const size_t global_wire =
                    static_cast<size_t>(participant) * slice + local_wire;
                (*global_coefficients)[lane * witness_slots + global_wire] = F(
                    static_cast<long long>(gathered_words[src_word] % F::mod),
                    static_cast<long long>(gathered_words[src_word + 1] % F::mod));
            }
        }
    }
    return true;
}

bool collective_shape_ok(bool local_ok, MPI_Comm comm) {
    int local = local_ok ? 1 : 0;
    int global = 0;
    int world_size = 0;
    MPI_Comm_size(comm, &world_size);
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, comm);
    record_control_allreduce(sizeof(int), world_size);
    return global == 1;
}

} // namespace

bool run_initial_packed_validity_gate(
    Runtime& runtime,
    const std::vector<F>& witness_share,
    const std::vector<F>& vL_share,
    const std::vector<F>& vR_share,
    const std::vector<F>& vO_share,
    const std::vector<std::vector<std::pair<int,int>>>& pA,
    const std::vector<std::vector<std::pair<int,int>>>& pB,
    const std::vector<std::vector<std::pair<int,int>>>& pC,
    const std::vector<StateId>& input_states,
    int k,
    int packed_width,
    InitialValidityGateResult* result,
    MPI_Comm comm) {
    if (!result) return false;
    *result = InitialValidityGateResult{};
    if (!runtime.enabled()) {
        result->valid = true;
        return true;
    }
    ExperimentControlTrafficScope traffic_scope(
        ExperimentControlTrafficKind::INITIAL_VALIDITY);

    int rank = -1;
    int world_size = 0;
    MPI_Comm_rank(comm, &rank);
    MPI_Comm_size(comm, &world_size);

    const bool local_shape_ok =
        rank >= 0 &&
        world_size == runtime.world_size() &&
        world_size >= 4 &&
        k > 0 &&
        packed_width > k &&
        packed_width * 2 == world_size &&
        k * 4 == world_size &&
        !witness_share.empty() &&
        !vL_share.empty() &&
        vL_share.size() == vR_share.size() &&
        vL_share.size() == vO_share.size();
    if (!collective_shape_ok(local_shape_ok, comm))
        return false;

    int domain_log = 0;
    if (!exact_log2(2 * world_size, &domain_log))
        return false;

    const int threshold = (world_size - 1) / 3;
    if (threshold <= 0 || 3 * threshold >= world_size)
        return false;

    const std::vector<F> expected_marker = {F(1)};
    std::vector<OperationRef> validation_predecessors;
    const OperationRef init_predecessor =
        runtime.latest_operation_ref(Phase::INIT);
    if (init_predecessor.object_id != 0)
        validation_predecessors.push_back(init_predecessor);
    const RecordId validation_record = runtime.register_vector_operation(
        Phase::INIT, 1, Obligation::DERIVE,
        expected_marker, validation_predecessors);
    if (validation_record == 0)
        return false;
    runtime.bind_state_dependencies(validation_record, input_states);
    const CheckpointId validation_checkpoint =
        runtime.checkpoint_id(Phase::INIT, 1);
    if (validation_checkpoint == 0)
        return false;

    AuthenticatedMpcExchange exchange(rank, world_size, comm);
    ReferenceShamirMpc mpc(rank, world_size, threshold, comm);
    if (!mpc.valid())
        return false;
    bool authenticated_transport_used = false;
    Digest transport_capability_binding{};
    if (exchange.production_authenticated_ready()) {
        if (!mpc.SetAuthenticatedTransport(
                &exchange, runtime.session_id(), validation_checkpoint))
            return false;
        authenticated_transport_used = true;
        transport_capability_binding = exchange.ProductionCapabilityBinding();
        if (transport_capability_binding == Digest{})
            return false;
    }

    bool strong_consistency_used = false;
    Digest consistency_capability_binding{};
    const MultiplicationConsistencyProofBackend* consistency_backend =
        MultiplicationConsistencyBackendRegistry::Current();
    const Digest consistency_acceptance_binding =
        MultiplicationConsistencyBackendRegistry::CurrentAcceptanceBinding();
    if (consistency_backend) {
        const auto capabilities = consistency_backend->Capabilities();
        if (!production_ready_multiplication_consistency_capabilities(
                capabilities) ||
            consistency_acceptance_binding == Digest{} ||
            !mpc.SetMultiplicationConsistencyProofBackend(
                consistency_backend) ||
            !mpc.multiplication_consistency_available())
            return false;
        consistency_capability_binding =
            mpc.multiplication_consistency_capability_binding();
        if (consistency_capability_binding == Digest{})
            return false;
        experiment_record_consistency_provider_status(
            true, true, true, capabilities.protocol_id);
        strong_consistency_used = true;
    } else {
        experiment_record_consistency_provider_status(
            false, false, false, 0);
    }

    Digest joint_seed{};
    Digest public_coin_binding{};
    if (!mpc.JointPublicSeed(&joint_seed, &public_coin_binding) ||
        joint_seed == Digest{} || public_coin_binding == Digest{})
        return false;

    const F root = getRootOfUnity(domain_log);
    std::vector<F> participant_points(static_cast<size_t>(world_size), F(0));
    for (int participant = 0; participant < world_size; ++participant) {
        participant_points[static_cast<size_t>(participant)] =
            F::fastPow(root, static_cast<__uint128_t>(2 * participant + 1));
    }

    const int source_stride = (2 * world_size) / packed_width;
    std::vector<F> local_lagrange(static_cast<size_t>(k), F(0));
    const F local_point = participant_points[static_cast<size_t>(rank)];
    for (int slot = 0; slot < k; ++slot) {
        const F target = F::fastPow(
            root, static_cast<__uint128_t>(source_stride * slot));
        F lambda(1);
        for (int other = 0; other < world_size; ++other) {
            if (other == rank) continue;
            const F other_point =
                participant_points[static_cast<size_t>(other)];
            lambda *= (target - other_point) *
                      (local_point - other_point).inv();
        }
        local_lagrange[static_cast<size_t>(slot)] = lambda;
    }

    const size_t witness_slots =
        witness_share.size() * static_cast<size_t>(k);
    const size_t constraint_slots =
        vL_share.size() * static_cast<size_t>(k);
    const Digest local_relation_binding = local_relation_partition_binding(
        pA, pB, pC, rank, world_size, witness_slots, constraint_slots);
    const Digest relation_binding = collective_relation_binding(
        local_relation_binding, world_size, comm);
    if (local_relation_binding == Digest{} || relation_binding == Digest{})
        return false;

    std::vector<F> global_wire_coefficients;
    if (!build_global_wire_coefficients(
            joint_seed, relation_binding, runtime.session_id(),
            rank, world_size, k, packed_width,
            witness_slots, constraint_slots,
            pA, pB, pC, &global_wire_coefficients, comm))
        return false;

    F local_additive_contribution(0);

    // Public R1CS linkage: observed vL/vR/vO slots minus the public
    // witness-to-wire linear map, compressed under domain-separated coins.
    const std::vector<const std::vector<F>*> lanes = {
        &vL_share, &vR_share, &vO_share};
    for (size_t lane = 0; lane < lanes.size(); ++lane) {
        const auto& lane_share = *lanes[lane];
        for (size_t constraint = 0; constraint < constraint_slots; ++constraint) {
            const size_t block = constraint / static_cast<size_t>(k);
            const int slot = static_cast<int>(
                constraint % static_cast<size_t>(k));
            const F rho = linkage_coefficient_from_seed(
                joint_seed, relation_binding, runtime.session_id(),
                world_size, k, packed_width,
                static_cast<int>(lane), constraint);
            local_additive_contribution +=
                rho * local_lagrange[static_cast<size_t>(slot)] *
                lane_share[block];
        }
    }
    for (size_t wire = 0; wire < witness_slots; ++wire) {
        const size_t block = wire / static_cast<size_t>(k);
        const int slot = static_cast<int>(wire % static_cast<size_t>(k));
        F coefficient(0);
        for (size_t lane = 0; lane < 3; ++lane)
            coefficient += global_wire_coefficients[
                lane * witness_slots + wire];
        local_additive_contribution -=
            coefficient * local_lagrange[static_cast<size_t>(slot)] *
            witness_share[block];
    }

    // Multiplicative R1CS residuals share the same final zero test, but use
    // a separate coefficient domain from the linear linkage relation.
    for (size_t block = 0; block < vL_share.size(); ++block) {
        const F local_residual =
            vL_share[block] * vR_share[block] - vO_share[block];
        F block_weight(0);
        for (int slot = 0; slot < k; ++slot) {
            const F rho = coefficient_from_seed(
                joint_seed, runtime.session_id(), world_size,
                k, packed_width, block, slot);
            block_weight +=
                rho * local_lagrange[static_cast<size_t>(slot)];
        }
        local_additive_contribution += local_residual * block_weight;
    }

    F compressed_share(0);
    ReferenceLinearSharingProvenance compressed_provenance;
    Digest compressed_sharing_binding{};
    if (!mpc.ShareLocalSumWithProvenance(
            local_additive_contribution, &compressed_share,
            &compressed_provenance, &compressed_sharing_binding) ||
        compressed_sharing_binding == Digest{} ||
        !validate_reference_linear_sharing_provenance(
            compressed_provenance) ||
        compressed_provenance.local_share != compressed_share)
        return false;

    bool is_zero = false;
    Digest zero_test_binding{};
    Digest multiplication_consistency_binding{};
    if (strong_consistency_used) {
        std::vector<u64> zero_context_words = {
            INITIAL_VALIDITY_BIND_DOMAIN,
            runtime.session_id(),
            validation_checkpoint,
            validation_record,
            static_cast<u64>(world_size),
            static_cast<u64>(k),
            static_cast<u64>(packed_width),
            static_cast<u64>(vL_share.size())};
        append_digest_words(joint_seed, &zero_context_words);
        append_digest_words(relation_binding, &zero_context_words);
        append_digest_words(
            consistency_acceptance_binding, &zero_context_words);
        append_digest_words(
            compressed_provenance.binding, &zero_context_words);
        const Digest zero_context_binding = hash_words(zero_context_words);
        if (zero_context_binding == Digest{})
            return false;

        ReferenceMaskedZeroConsistencyContext zero_context;
        zero_context.sid = runtime.session_id();
        zero_context.checkpoint = validation_checkpoint;
        zero_context.multiplication_id = validation_record;
        zero_context.context_binding = zero_context_binding;
        if (!mpc.MaskedZeroTestWithConsistency(
                compressed_provenance, zero_context,
                &is_zero, &zero_test_binding,
                &multiplication_consistency_binding) ||
            zero_test_binding == Digest{} ||
            multiplication_consistency_binding == Digest{})
            return false;
    } else {
        if (!mpc.MaskedZeroTest(
                compressed_share, &is_zero, &zero_test_binding) ||
            zero_test_binding == Digest{})
            return false;
    }

    std::vector<u64> binding_words = {
        INITIAL_VALIDITY_BIND_DOMAIN,
        runtime.session_id(),
        static_cast<u64>(world_size),
        static_cast<u64>(k),
        static_cast<u64>(packed_width),
        static_cast<u64>(vL_share.size()),
        static_cast<u64>(threshold),
        is_zero ? 1ULL : 0ULL,
        authenticated_transport_used ? 1ULL : 0ULL,
        strong_consistency_used ? 1ULL : 0ULL};
    append_digest_words(joint_seed, &binding_words);
    append_digest_words(public_coin_binding, &binding_words);
    append_digest_words(relation_binding, &binding_words);
    append_digest_words(compressed_provenance.binding, &binding_words);
    append_digest_words(compressed_sharing_binding, &binding_words);
    if (authenticated_transport_used)
        append_digest_words(transport_capability_binding, &binding_words);
    if (strong_consistency_used) {
        append_digest_words(
            consistency_capability_binding, &binding_words);
        append_digest_words(
            consistency_acceptance_binding, &binding_words);
        append_digest_words(
            multiplication_consistency_binding, &binding_words);
    }
    append_digest_words(zero_test_binding, &binding_words);
    const Digest validation_binding = hash_words(binding_words);
    if (validation_binding == Digest{})
        return false;

    experiment_record_initial_validity(strong_consistency_used);

    result->executed = true;
    result->valid = is_zero;
    result->public_coin_binding = public_coin_binding;
    result->zero_test_binding = zero_test_binding;
    result->validation_binding = validation_binding;
    result->relation_definition_binding = relation_binding;
    result->transport_capability_binding = transport_capability_binding;
    result->compressed_sharing_binding = compressed_provenance.binding;
    result->consistency_capability_binding =
        consistency_capability_binding;
    result->consistency_acceptance_binding =
        consistency_acceptance_binding;
    result->multiplication_consistency_binding =
        multiplication_consistency_binding;
    result->authenticated_transport_used = authenticated_transport_used;
    result->strong_consistency_used = strong_consistency_used;
    result->packed_blocks = vL_share.size();
    result->linked_witness_slots = witness_slots;
    result->linked_constraint_slots = constraint_slots;
    result->reference_threshold = threshold;

    std::vector<u64> public_aux = {
        static_cast<u64>(world_size),
        static_cast<u64>(k),
        static_cast<u64>(packed_width),
        static_cast<u64>(vL_share.size()),
        static_cast<u64>(witness_slots),
        static_cast<u64>(constraint_slots),
        static_cast<u64>(threshold),
        authenticated_transport_used ? 1ULL : 0ULL,
        strong_consistency_used ? 1ULL : 0ULL};
    append_digest_words(relation_binding, &public_aux);
    append_digest_words(compressed_provenance.binding, &public_aux);
    if (authenticated_transport_used)
        append_digest_words(transport_capability_binding, &public_aux);
    if (strong_consistency_used) {
        append_digest_words(
            consistency_capability_binding, &public_aux);
        append_digest_words(
            consistency_acceptance_binding, &public_aux);
        append_digest_words(
            multiplication_consistency_binding, &public_aux);
    }
    append_digest_words(validation_binding, &public_aux);
    runtime.bind_public_word_aux(
        validation_record, AuditPublicAuxKind::GENERIC_WORDS, public_aux);
    const std::vector<F> actual_marker = {is_zero ? F(1) : F(0)};
    runtime.activate_vector(validation_record, actual_marker);
    runtime.record_pending_relation_violation();
    runtime.consume_pending();
    runtime.seal_checkpoint_instance(Phase::INIT, 1);

    result->validation_operation.owner = static_cast<uint32_t>(rank);
    result->validation_operation.object_id = validation_record;

    if (!is_zero)
        return true;

    std::vector<F> validated_material = witness_share;
    validated_material.push_back(digest_to_field(validation_binding));
    const StateId validated_state = runtime.import_state(
        "validated_witness", Phase::INIT, validated_material);
    if (validated_state == 0)
        return false;

    result->validated_state = validated_state;

    if (runtime.verbose() && rank == 0) {
        std::cout << "[PVIA][validity] PASS blocks="
                  << result->packed_blocks
                  << " witness_slots=" << result->linked_witness_slots
                  << " constraint_slots=" << result->linked_constraint_slots
                  << " reference_threshold=" << threshold
                  << " bound_transport="
                  << (authenticated_transport_used ? "yes" : "no") << "\n";
    }
    return true;
}

} // namespace pvia
