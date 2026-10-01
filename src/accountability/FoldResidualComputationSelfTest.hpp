#pragma once

namespace pvia {

// Development-only computation test. It verifies deterministic residual
// derivation and fail-closed authentication semantics; it does not install a
// PRIVATE_RECOVERY secure composition.
bool run_fold_residual_computation_selftest();

} // namespace pvia
