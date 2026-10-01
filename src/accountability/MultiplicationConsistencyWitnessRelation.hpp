#pragma once

#include "MultiplicationConsistencyProof.hpp"

namespace pvia {

// Private-side conformance check for the witness relation presented to an
// external provider. This validates the concrete relation and provenance
// encodings; it is not the public proof verification step.
bool validate_multiplication_consistency_provider_witness_relation(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyWitness& witness);

} // namespace pvia
