#pragma once

#include "MultiplicationConsistencyProof.hpp"
#include "MultiplicationConsistencyProviderAbiC.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace pvia {

constexpr uint32_t MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_VERSION =
    PVIA_MC_ABI_VERSION;

std::vector<uint64_t> encode_multiplication_consistency_statement_abi(
    const MultiplicationConsistencyStatement& statement);
bool decode_multiplication_consistency_statement_abi(
    const std::vector<uint64_t>& words,
    MultiplicationConsistencyStatement* statement);

std::vector<uint64_t> encode_multiplication_consistency_witness_abi(
    const MultiplicationConsistencyWitness& witness);
bool decode_multiplication_consistency_witness_abi(
    const std::vector<uint64_t>& words,
    MultiplicationConsistencyWitness* witness);

std::vector<uint64_t> encode_multiplication_consistency_capabilities_abi(
    const MultiplicationConsistencyCapabilities& capabilities);
bool decode_multiplication_consistency_capabilities_abi(
    const std::vector<uint64_t>& words,
    MultiplicationConsistencyCapabilities* capabilities);

using MultiplicationConsistencyAbiVersionFn =
    pvia_mc_provider_abi_version_fn;
using MultiplicationConsistencyAbiCapabilitiesFn =
    pvia_mc_provider_capabilities_fn;
using MultiplicationConsistencyAbiProveFn =
    pvia_mc_provider_prove_fn;
using MultiplicationConsistencyAbiVerifyFn =
    pvia_mc_provider_verify_fn;

constexpr const char* MULTIPLICATION_CONSISTENCY_ABI_VERSION_SYMBOL =
    PVIA_MC_ABI_VERSION_SYMBOL_NAME;
constexpr const char* MULTIPLICATION_CONSISTENCY_ABI_CAPABILITIES_SYMBOL =
    PVIA_MC_ABI_CAPABILITIES_SYMBOL_NAME;
constexpr const char* MULTIPLICATION_CONSISTENCY_ABI_PROVE_SYMBOL =
    PVIA_MC_ABI_PROVE_SYMBOL_NAME;
constexpr const char* MULTIPLICATION_CONSISTENCY_ABI_VERIFY_SYMBOL =
    PVIA_MC_ABI_VERIFY_SYMBOL_NAME;

} // namespace pvia
