#pragma once

#include "PVIA.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace pvia {

struct AccountabilitySignatureCapabilities {
    bool available = false;
    uint64_t scheme_id = 0;
    bool post_quantum = false;
    bool hash_based = false;
    bool deterministic = false;
    bool variable_length_signature = false;
    size_t private_key_bytes = 0;
    size_t public_key_bytes = 0;
    size_t signature_bytes = 0;
    Digest implementation_binding{};
    Digest capability_binding{};
};

struct AccountabilitySignatureRequirements {
    bool require_post_quantum = false;
    bool require_hash_based = false;
    bool allow_variable_length_signature = true;
};

Digest compute_accountability_signature_capability_binding(
    const AccountabilitySignatureCapabilities& capabilities);
bool validate_accountability_signature_capabilities(
    const AccountabilitySignatureCapabilities& capabilities);
bool accountability_signature_satisfies(
    const AccountabilitySignatureCapabilities& capabilities,
    const AccountabilitySignatureRequirements& requirements);

class AccountabilitySignatureBackend {
public:
    virtual ~AccountabilitySignatureBackend() = default;

    virtual AccountabilitySignatureCapabilities Capabilities() const = 0;
    virtual bool GenerateKeypair(
        std::vector<uint8_t>* private_key,
        std::vector<uint8_t>* public_key) const = 0;
    virtual bool DerivePublicKey(
        const std::vector<uint8_t>& private_key,
        std::vector<uint8_t>* public_key) const = 0;
    virtual bool Sign(
        const std::vector<uint8_t>& private_key,
        const uint8_t* message, size_t message_size,
        std::vector<uint8_t>* signature) const = 0;
    virtual bool Verify(
        const std::vector<uint8_t>& public_key,
        const uint8_t* message, size_t message_size,
        const std::vector<uint8_t>& signature) const = 0;
};

} // namespace pvia
