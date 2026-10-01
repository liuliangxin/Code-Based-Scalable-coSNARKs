#pragma once

#include <cstddef>

namespace pvia {

bool run_reference_residual_mpc_selftest(int rank, int world_size);

bool run_reference_residual_localization_benchmark(
    int rank, int world_size, size_t total_operations,
    bool fault_last);

} // namespace pvia
