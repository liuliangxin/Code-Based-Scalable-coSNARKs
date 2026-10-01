#pragma once

#include "AccountabilitySignature.hpp"

namespace pvia {

class Ed25519AccountabilitySignatureBackend final
    : public AccountabilitySignatureBackend {
public:
    AccountabilitySignatureCapabilities Capabilities() const override;
    bool GenerateKeypair(
        std::vector<uint8_t>* private_key,
        std::vector<uint8_t>* public_key) const override;
    bool DerivePublicKey(
        const std::vector<uint8_t>& private_key,
        std::vector<uint8_t>* public_key) const override;
    bool Sign(
        const std::vector<uint8_t>& private_key,
        const uint8_t* message, size_t message_size,
        std::vector<uint8_t>* signature) const override;
    bool Verify(
        const std::vector<uint8_t>& public_key,
        const uint8_t* message, size_t message_size,
        const std::vector<uint8_t>& signature) const override;
};

const Ed25519AccountabilitySignatureBackend&
ed25519_accountability_signature_backend();

} // namespace pvia
