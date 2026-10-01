#pragma once

#include "ExperimentMetrics.hpp"

#include <cstddef>
#include <cstdint>

namespace pvia {

inline void record_control_all_peer_exchange(
    uint64_t bytes_per_peer, int world_size) {
    if (world_size <= 1) {
        experiment_add_protocol_control_traffic(0, 0, 0, 0, 1);
        return;
    }
    const uint64_t peers = static_cast<uint64_t>(world_size - 1);
    experiment_add_protocol_control_traffic(
        peers * bytes_per_peer, peers * bytes_per_peer,
        peers, peers, 1);
}

inline void record_control_allgather(
    uint64_t local_bytes, int world_size) {
    record_control_all_peer_exchange(local_bytes, world_size);
}

inline void record_control_allreduce(
    uint64_t local_bytes, int world_size) {
    record_control_all_peer_exchange(local_bytes, world_size);
}

inline void record_control_broadcast(
    uint64_t bytes, int root, int rank, int world_size) {
    if (world_size <= 1) {
        experiment_add_protocol_control_traffic(0, 0, 0, 0, 1);
        return;
    }
    const uint64_t peers = static_cast<uint64_t>(world_size - 1);
    if (rank == root) {
        experiment_add_protocol_control_traffic(
            peers * bytes, 0, peers, 0, 1);
    } else {
        experiment_add_protocol_control_traffic(
            0, bytes, 0, 1, 1);
    }
}

inline void record_control_scatter(
    uint64_t bytes_per_rank, int root, int rank, int world_size) {
    record_control_broadcast(bytes_per_rank, root, rank, world_size);
}

inline void record_control_gather(
    uint64_t bytes_per_rank, int root, int rank, int world_size) {
    if (world_size <= 1) {
        experiment_add_protocol_control_traffic(0, 0, 0, 0, 1);
        return;
    }
    const uint64_t peers = static_cast<uint64_t>(world_size - 1);
    if (rank == root) {
        experiment_add_protocol_control_traffic(
            0, peers * bytes_per_rank, 0, peers, 1);
    } else {
        experiment_add_protocol_control_traffic(
            bytes_per_rank, 0, 1, 0, 1);
    }
}

} // namespace pvia
