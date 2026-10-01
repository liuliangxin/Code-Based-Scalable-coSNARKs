#pragma once

#include "PVIA.hpp"

#include <mpi.h>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace pvia {

struct JointPackedPreprocessingResult {
    bool ok = false;
    size_t share_count = 0;
    int contributors = 0;
    Digest local_binding{};
};

bool generate_joint_packed_random_share(
    size_t share_count, int world_size, int k, int packed_width,
    uint64_t domain, std::vector<F>* local_share,
    JointPackedPreprocessingResult* result = nullptr,
    MPI_Comm comm = MPI_COMM_WORLD);

} // namespace pvia
