#include "ExternalMultiplicationConsistencyProofAdapter.hpp"
#include "MultiplicationConsistencyWitnessRelation.hpp"
#include "MultiplicationConsistencyProviderAbi.hpp"
#include "MultiplicationConsistencyProviderAbiHelpers.h"

#include <utility>

namespace pvia {

ExternalMultiplicationConsistencyProofAdapter::
ExternalMultiplicationConsistencyProofAdapter(
    MultiplicationConsistencyCapabilities capabilities,
    uint32_t expected_proof_system_id,
    MultiplicationConsistencyProviderCallbacks callbacks)
    : capabilities_(std::move(capabilities)),
      expected_proof_system_id_(expected_proof_system_id),
      callbacks_(std::move(callbacks)) {
    ready_ =
        expected_proof_system_id_ != 0 &&
        production_ready_multiplication_consistency_capabilities(
            capabilities_) &&
        static_cast<bool>(callbacks_.prove) &&
        static_cast<bool>(callbacks_.verify);
}

MultiplicationConsistencyCapabilities
ExternalMultiplicationConsistencyProofAdapter::Capabilities() const {
    return ready_ ? capabilities_ : MultiplicationConsistencyCapabilities{};
}

MultiplicationConsistencyProofArtifact
ExternalMultiplicationConsistencyProofAdapter::Prove(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyWitness& witness) const {
    MultiplicationConsistencyProofArtifact proof;
    if (!ready_ ||
        !validate_multiplication_consistency_statement(statement) ||
        !validate_multiplication_consistency_provider_witness_relation(
            statement, witness))
        return proof;

    const auto statement_words =
        encode_multiplication_consistency_statement_abi(statement);
    const auto witness_words =
        encode_multiplication_consistency_witness_abi(witness);
    pvia_mc_statement_view c_statement{};
    pvia_mc_witness_view c_witness{};
    if (!pvia_mc_parse_statement(
            statement_words.data(), statement_words.size(),
            &c_statement) ||
        !pvia_mc_parse_witness(
            witness_words.data(), witness_words.size(),
            &c_witness) ||
        !pvia_mc_validate_witness_payloads(&c_witness))
        return proof;

    proof = callbacks_.prove(statement, witness);
    if (proof.proof_system_id != expected_proof_system_id_ ||
        !validate_multiplication_consistency_proof_artifact(
            statement, proof) ||
        !callbacks_.verify(statement, proof))
        return MultiplicationConsistencyProofArtifact{};
    return proof;
}

bool ExternalMultiplicationConsistencyProofAdapter::Verify(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyProofArtifact& proof) const {
    return ready_ &&
        proof.proof_system_id == expected_proof_system_id_ &&
        validate_multiplication_consistency_statement(statement) &&
        validate_multiplication_consistency_proof_artifact(
            statement, proof) &&
        callbacks_.verify(statement, proof);
}

} // namespace pvia
