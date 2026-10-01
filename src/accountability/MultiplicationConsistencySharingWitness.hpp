#pragma once

#include "PVIA.hpp"

#include <cstdint>
#include <vector>

namespace pvia {

enum class MultiplicationConsistencySharingWitnessKind : uint64_t {
    VSS_LOCAL = 1,
    LINEAR_COMBINATION = 2,
    VSS_DEALER = 3,
};

struct MultiplicationConsistencySharingWitnessEnvelope {
    MultiplicationConsistencySharingWitnessKind kind =
        MultiplicationConsistencySharingWitnessKind::VSS_LOCAL;
    Digest sharing_binding{};
    std::vector<u64> payload_words;
};

bool validate_multiplication_consistency_sharing_witness(
    const MultiplicationConsistencySharingWitnessEnvelope& witness);

std::vector<u64> encode_multiplication_consistency_sharing_witness(
    const MultiplicationConsistencySharingWitnessEnvelope& witness);

bool decode_multiplication_consistency_sharing_witness(
    const std::vector<u64>& words,
    MultiplicationConsistencySharingWitnessEnvelope* witness);

bool wrap_reference_multiplication_consistency_sharing_witness(
    MultiplicationConsistencySharingWitnessKind kind,
    const std::vector<u64>& payload_words,
    const Digest& expected_binding,
    std::vector<u64>* encoded);

bool wrap_reference_multiplication_consistency_input_sharing_witness(
    const std::vector<u64>& payload_words,
    const Digest& expected_binding,
    std::vector<u64>* encoded);

} // namespace pvia
