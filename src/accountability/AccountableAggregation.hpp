#pragma once

#include "PVIA.hpp"
#include <array>
#include <mpi.h>
#include <string>
#include <vector>

namespace pvia {

inline std::vector<u64> serialize_field_vector_for_meta(
    const std::vector<F>& values) {
    std::vector<u64> words;
    words.reserve(values.size() * 2);
    for (const auto& value : values) {
        words.push_back(value.real);
        words.push_back(value.img);
    }
    return words;
}

inline std::vector<F> make_aggregation_aux(
    const std::vector<F>& weights, int N, int k = -1, int _k = -1) {
    std::vector<F> aux = weights;
    aux.push_back(F(N));
    if (k >= 0) aux.push_back(F(k));
    if (_k >= 0) aux.push_back(F(_k));
    return aux;
}


inline std::array<u64, META_WORDS> bind_rank0_aggregate(
    std::vector<F>& aggregate, const char* release_name, int rank,
    const std::vector<F>& aggregation_aux = {},
    AuditRelationKernel aggregate_kernel = AuditRelationKernel::AGGREGATE_CODED) {
    std::array<u64, META_WORDS> meta{};
    Runtime& runtime = Runtime::instance();
    (void)release_name;
    if (!runtime.enabled() || rank != 0) return meta;

    const uint32_t round = runtime.pending_round();
    const Phase phase = runtime.pending_phase();
    const std::vector<OperationRef> contributors =
        runtime.checkpoint_operations(phase, round, Obligation::DERIVE);
    const RecordId aggregate_record = runtime.register_vector_operation(
        phase, round, Obligation::AGGREGATE, aggregate, contributors);
    runtime.bind_relation_kernel(aggregate_record, aggregate_kernel);
    if (!aggregation_aux.empty()) {
        runtime.bind_public_field_aux(
            aggregate_record, AuditPublicAuxKind::AGGREGATION_WEIGHTS,
            aggregation_aux);
    }
    runtime.activate_vector(aggregate_record, aggregate);
    runtime.record_pending_relation_violation();

    const RecordId publish_record = runtime.prepare_followup_vector(
        Obligation::PUBLISH, aggregate);
    runtime.bind_relation_kernel(
        publish_record, AuditRelationKernel::PUBLISH_AGGREGATE);
    runtime.activate_vector(publish_record, aggregate);

    const auto payload = serialize_field_vector_for_meta(aggregate);
    meta = runtime.make_pending_meta(payload, false);
    runtime.observe_local_payload(payload);
    return meta;
}
inline void publish_rank0_aggregate_meta(
    std::array<u64, META_WORDS> meta,
    const std::vector<u64>& actual_payload,
    int rank) {
    Runtime& runtime = Runtime::instance();
    if (!runtime.enabled()) return;

    int seal_ok = 1;
    if (rank == 0) {
        seal_ok = runtime.seal_transfer_meta(meta, actual_payload) ? 1 : 0;
        if (seal_ok) runtime.observe_outgoing_transfer(meta, actual_payload);
    }
    MPI_Bcast(&seal_ok, 1, MPI_INT, 0, MPI_COMM_WORLD);
    if (!seal_ok) return;
    MPI_Bcast(meta.data(), META_WORDS, MPI_UINT64_T, 0, MPI_COMM_WORLD);
    if (rank != 0) {
        runtime.observe_remote_meta(0, meta, actual_payload);
    }
    if (meta[0] == META_MAGIC) {
        runtime.seal_checkpoint_instance(
            static_cast<Phase>(static_cast<uint32_t>(meta[2])),
            static_cast<uint32_t>(meta[3]));
    }
}

} // namespace pvia
