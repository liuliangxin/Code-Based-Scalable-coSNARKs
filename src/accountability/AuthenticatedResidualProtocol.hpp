#pragma once

#include "CollectiveResidualEngine.hpp"
#include "ResidualChallengeTranscript.hpp"

namespace pvia {

struct ParticipantResidualCommitment {
    uint32_t owner = 0;
    size_t handle_count = 0;
    Digest descriptor_digest{};
    Digest local_commitment_root{};
    Digest authentication_commitment{};
};

struct CollectiveResidualCommitmentSet {
    bool available = false;
    bool cryptographically_authenticated = false;
    CheckpointId checkpoint = 0;
    std::vector<ParticipantResidualCommitment> participants;
    Digest security_attestation_binding{};
    Digest root{};
};

struct ResidualSubsetDescriptor {
    CheckpointId checkpoint = 0;
    uint32_t depth = 0;
    std::vector<OperationRef> operations;
    Digest batch_result_binding{};
    Digest challenge_transcript_binding{};
    Digest security_attestation_binding{};
    Digest binding{};
};

struct ResidualSubsetCheckResult {
    bool available = false;
    bool cryptographically_authenticated = false;
    bool failed = false;
    CheckpointId checkpoint = 0;
    Digest batch_result_binding{};
    Digest challenge_transcript_binding{};
    Digest security_attestation_binding{};
    Digest subset_binding{};
    Digest proof_commitment{};
};

Digest compute_participant_commitment_root(
    const std::vector<ParticipantResidualCommitment>& participants);
Digest compute_collective_residual_commitment_root(
    const std::vector<ParticipantResidualCommitment>& participants,
    const Digest& security_attestation_binding);
bool validate_participant_commitment_set(
    const ObligationSet& scope,
    const CollectiveBatchDescriptor& local_descriptor,
    const CollectiveResidualCommitmentSet& commitments,
    int world_size);

ResidualSubsetDescriptor make_residual_subset_descriptor(
    const BatchCheckResult& batch,
    const std::vector<OperationRef>& operations,
    uint32_t depth);
bool validate_residual_subset_check(
    const BatchCheckResult& batch,
    const ResidualSubsetDescriptor& subset,
    const ResidualSubsetCheckResult& result);

// Cryptographic boundary for the paper-level collective residual protocol.
// Implementations MUST keep clear residuals private/authenticated and MUST bind
// every collective result to the canonical scope and participant commitments.
class AuthenticatedResidualProtocol {
public:
    virtual ~AuthenticatedResidualProtocol() = default;

    // Required semantics:
    //  1. commit/authenticate every participant's selected residual handles;
    //  2. derive a common unpredictable challenge only after those commitments;
    //  3. evaluate an authenticated random linear combination of residuals;
    //  4. reveal only the authenticated zero/non-zero result and commitments.
    virtual CollectiveResidualCommitmentSet CommitResidualBatch(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& local_descriptor,
        const LocalResidualBatchView& local_view,
        int rank,
        int world_size) const = 0;

    virtual AuthenticatedChallengeTranscript DeriveJointChallenge(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& local_descriptor,
        const CollectiveResidualCommitmentSet& commitments,
        int rank,
        int world_size) const = 0;

    virtual BatchCheckResult RandomLinearBatchCheck(
        const ObligationSet& scope,
        const CollectiveBatchDescriptor& local_descriptor,
        const LocalResidualBatchView& local_view,
        const CollectiveResidualCommitmentSet& commitments,
        const AuthenticatedChallengeTranscript& challenge_transcript,
        int rank,
        int world_size) const = 0;

    // Authenticated subset test used by recursive localization. The protocol
    // reveals only whether the selected subset contains a non-zero residual.
    virtual ResidualSubsetCheckResult CheckResidualSubset(
        const ObligationSet& scope,
        const BatchCheckResult& batch,
        const ResidualSubsetDescriptor& subset,
        const LocalResidualBatchView& local_view,
        int rank,
        int world_size) const = 0;

    // Bind the final singleton accusation and its public operation descriptor
    // (label/digests/statement commitment) to the recursive dispute transcript.
    virtual CollectiveDisputeResult FinalizeLocalization(
        const ObligationSet& scope,
        const BatchCheckResult& batch,
        const OperationRef& accused,
        const Digest& recursive_transcript_binding,
        const LocalResidualBatchView& local_view,
        int rank,
        int world_size) const = 0;
};
class ProtocolBackedCollectiveResidualEngine final
    : public CollectiveResidualEngine {
public:
    explicit ProtocolBackedCollectiveResidualEngine(
        const AuthenticatedResidualProtocol& protocol)
        : protocol_(protocol) {}

    BatchCheckResult BatchCheck(
        const ObligationSet& scope,
        const LocalResidualBatchView& local_view,
        int rank,
        int world_size) const override;

    CollectiveDisputeResult Dispute(
        const ObligationSet& scope,
        const BatchCheckResult& batch,
        const LocalResidualBatchView& local_view,
        int rank,
        int world_size) const override;

private:
    const AuthenticatedResidualProtocol& protocol_;
};

} // namespace pvia
