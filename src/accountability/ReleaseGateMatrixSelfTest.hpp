#pragma once

namespace pvia {

class Runtime;

bool run_release_gate_matrix_selftest(
    Runtime& runtime, int rank, int world_size);

} // namespace pvia
