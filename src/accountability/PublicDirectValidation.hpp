#pragma once

#include "PVIA.hpp"

#include <mpi.h>
#include <vector>

namespace pvia {

enum class PublicDirectValidationKind : uint32_t {
    R1CS_REDUCTION = 1,
    R_AGGREGATION = 2,
    BETA_SHARES = 3
};

struct PublicDirectValidationResult {
    bool executed = false;
    bool local_valid = false;
    bool collective_valid = false;
    RecordId record_id = 0;
    Digest context_binding{};
    Digest collective_binding{};
    std::vector<u64> encoded_bundle;
};

Digest compute_public_direct_context_binding(
    PublicDirectValidationKind kind,
    const std::vector<F>& public_context_fields,
    const std::vector<u64>& public_context_words);

bool verify_encoded_public_direct_validation_bundle(
    const std::vector<u64>& encoded_bundle,
    uint64_t expected_session_id,
    PublicDirectValidationKind expected_kind,
    const std::vector<Digest>& expected_context_bindings,
    Digest* collective_binding = nullptr);

bool validate_public_direct_vector(
    Runtime& runtime,
    PublicDirectValidationKind kind,
    const std::vector<F>& expected,
    const std::vector<F>& actual,
    const std::vector<F>& public_context_fields,
    const std::vector<u64>& public_context_words,
    PublicDirectValidationResult* result,
    MPI_Comm comm = MPI_COMM_WORLD);

} // namespace pvia
