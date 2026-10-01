#pragma once

#include "PVIA.hpp"

#include <vector>

namespace pvia {

struct RegistrationConsistencyStatement {
    uint64_t sid = 0;
    CheckpointId checkpoint = 0;
    OperationRef ref{};
    AuditRelationKernel kernel = AuditRelationKernel::UNKNOWN;
    size_t state_element_count = 0;
    size_t output_element_count = 0;
    Digest public_state_digest{};
    Digest public_actual_digest{};
    Digest operation_statement_binding{};
    Digest sharing_transcript_binding{};
    Digest statement_binding{};
};

Digest compute_registration_consistency_statement_binding(
    const RegistrationConsistencyStatement& statement);
bool validate_registration_consistency_statement(
    const RegistrationConsistencyStatement& statement);
struct RegistrationConsistencyProofArtifact {
    bool available = false;
    bool cryptographically_authenticated = false;
    bool zero_knowledge = false;
    uint32_t proof_system_id = 0;
    Digest statement_binding{};
    Digest transcript_binding{};
    Digest proof_commitment{};
    std::vector<u64> proof_words;
};

Digest compute_registration_consistency_proof_commitment(
    const RegistrationConsistencyProofArtifact& proof);
bool validate_registration_consistency_proof_artifact(
    const RegistrationConsistencyStatement& statement,
    const RegistrationConsistencyProofArtifact& proof);
Digest compute_registration_consistency_set_binding(
    const std::vector<RegistrationConsistencyProofArtifact>& proofs);

struct RegistrationConsistencyCapabilities {
    bool available = false;
    bool malicious_sound = false;
    bool zero_knowledge = false;
    bool binds_sharing_transcript = false;
    uint64_t protocol_id = 0;
    Digest implementation_binding{};
    Digest capability_binding{};
};

Digest compute_registration_consistency_capability_binding(
    const RegistrationConsistencyCapabilities& capabilities);
bool validate_registration_consistency_capabilities(
    const RegistrationConsistencyCapabilities& capabilities);
bool production_ready_registration_consistency_capabilities(
    const RegistrationConsistencyCapabilities& capabilities);

struct RegistrationConsistencyWitness {
    std::vector<F> state_values;
    std::vector<F> actual_output;
    std::vector<u64> sharing_witness_words;
};

class RegistrationConsistencyProofBackend {
public:
    virtual ~RegistrationConsistencyProofBackend() = default;
    virtual RegistrationConsistencyCapabilities Capabilities() const = 0;
    virtual RegistrationConsistencyProofArtifact Prove(
        const RegistrationConsistencyStatement& statement,
        const RegistrationConsistencyWitness& witness) const = 0;
    virtual bool Verify(
        const RegistrationConsistencyStatement& statement,
        const RegistrationConsistencyProofArtifact& proof) const = 0;
};
class FailClosedRegistrationConsistencyProofBackend final
    : public RegistrationConsistencyProofBackend {
public:
    RegistrationConsistencyCapabilities Capabilities() const override;
    RegistrationConsistencyProofArtifact Prove(
        const RegistrationConsistencyStatement& statement,
        const RegistrationConsistencyWitness& witness) const override;
    bool Verify(
        const RegistrationConsistencyStatement& statement,
        const RegistrationConsistencyProofArtifact& proof) const override;
};

} // namespace pvia
