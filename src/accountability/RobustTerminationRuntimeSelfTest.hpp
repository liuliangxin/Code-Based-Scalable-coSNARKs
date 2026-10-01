#pragma once

namespace pvia {

class Runtime;

// Runtime-only regression: an unavailable robust audit with a detectable,
// unattributable termination must fail closed without entering blame lifting.
bool run_robust_termination_runtime_selftest(
    Runtime& runtime, int rank, int world_size);

} // namespace pvia
