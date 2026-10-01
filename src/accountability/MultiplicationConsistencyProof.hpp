#pragma once

#include "PVIA.hpp"

#include <vector>

namespace pvia {

struct MultiplicationConsistencyStatement {
    uint64_t sid = 0;
    CheckpointId checkpoint = 0;
    uint64_t multiplication_id = 0;
    uint32_t dealer = 0;
    Digest lhs_sharing_binding{};
    Digest rhs_sharing_binding{};
    Digest output_sharing_binding{};
    Digest context_binding{};
    Digest statement_binding{};
};

Digest compute_multiplication_consistency_statement_binding(
    const MultiplicationConsistencyStatement& statement);
bool validate_multiplication_consistency_statement(
    const MultiplicationConsistencyStatement& statement);
struct MultiplicationConsistencyProofArtifact {
    bool available = false;
    bool cryptographically_authenticated = false;
    bool zero_knowledge = false;
    uint32_t proof_system_id = 0;
    Digest statement_binding{};
    Digest transcript_binding{};
    Digest proof_commitment{};
    std::vector<u64> proof_words;
};

Digest compute_multiplication_consistency_proof_commitment(
    const MultiplicationConsistencyProofArtifact& proof);
bool validate_multiplication_consistency_proof_artifact(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyProofArtifact& proof);
std::vector<u64> encode_multiplication_consistency_proof_artifact(
    const MultiplicationConsistencyProofArtifact& proof);
bool decode_multiplication_consistency_proof_artifact(
    const std::vector<u64>& words,
    MultiplicationConsistencyProofArtifact* proof);
Digest compute_multiplication_consistency_set_binding(
    const std::vector<MultiplicationConsistencyProofArtifact>& proofs);

struct MultiplicationConsistencyCapabilities {
    bool available = false;
    bool malicious_sound = false;
    bool zero_knowledge = false;
    bool binds_input_sharings = false;
    bool binds_output_sharing = false;
    uint64_t protocol_id = 0;
    Digest relation_binding{};
    Digest implementation_binding{};
    Digest capability_binding{};
};

Digest compute_multiplication_consistency_relation_binding();
Digest compute_multiplication_consistency_capability_binding(
    const MultiplicationConsistencyCapabilities& capabilities);
bool validate_multiplication_consistency_capabilities(
    const MultiplicationConsistencyCapabilities& capabilities);
bool production_ready_multiplication_consistency_capabilities(
    const MultiplicationConsistencyCapabilities& capabilities);

struct MultiplicationConsistencyWitness {
    F lhs_share{};
    F rhs_share{};
    F product_value{};
    // Private prover material for proving membership/derivation of each input
    // sharing and generation of the output VSS sharing. None is serialized in
    // the public proof artifact by this interface.
    std::vector<u64> lhs_sharing_witness_words;
    std::vector<u64> rhs_sharing_witness_words;
    std::vector<u64> output_sharing_witness_words;
};

bool validate_multiplication_consistency_witness_for_statement(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyWitness& witness);

class MultiplicationConsistencyProofBackend {
public:
    virtual ~MultiplicationConsistencyProofBackend() = default;
    virtual MultiplicationConsistencyCapabilities Capabilities() const = 0;
    virtual MultiplicationConsistencyProofArtifact Prove(
        const MultiplicationConsistencyStatement& statement,
        const MultiplicationConsistencyWitness& witness) const = 0;
    virtual bool Verify(
        const MultiplicationConsistencyStatement& statement,
        const MultiplicationConsistencyProofArtifact& proof) const = 0;
};

class FailClosedMultiplicationConsistencyProofBackend final
    : public MultiplicationConsistencyProofBackend {
public:
    MultiplicationConsistencyCapabilities Capabilities() const override;
    MultiplicationConsistencyProofArtifact Prove(
        const MultiplicationConsistencyStatement& statement,
        const MultiplicationConsistencyWitness& witness) const override;
    bool Verify(
        const MultiplicationConsistencyStatement& statement,
        const MultiplicationConsistencyProofArtifact& proof) const override;
};

} // namespace pvia
