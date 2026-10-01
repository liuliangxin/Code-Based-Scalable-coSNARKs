#pragma once

#include "AuthenticatedMpcExchange.hpp"
#include "TransferAuthentication.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace pvia {

struct AuthenticatedMpcAbortEvidenceCapabilities {
    bool available = false;
    bool signed_equivocation = false;
    bool public_registry_verification = false;
    bool external_registry_anchor_required = false;
    bool payload_binding_signatures = false;
    bool payload_contents_redacted = false;
    uint64_t protocol_id = 0;
    Digest transport_capability_binding{};
    Digest implementation_binding{};
    Digest capability_binding{};
};

Digest compute_authenticated_mpc_abort_evidence_capability_binding(
    const AuthenticatedMpcAbortEvidenceCapabilities& capabilities);
bool validate_authenticated_mpc_abort_evidence_capabilities(
    const AuthenticatedMpcAbortEvidenceCapabilities& capabilities);
bool production_ready_authenticated_mpc_abort_evidence_capabilities(
    const AuthenticatedMpcAbortEvidenceCapabilities& capabilities);
AuthenticatedMpcAbortEvidenceCapabilities
make_signed_equivocation_abort_evidence_capabilities(
    const Digest& transport_capability_binding);

enum class AuthenticatedMpcAbortEvidenceKind : uint32_t {
    UNKNOWN = 0,
    SIGNED_EQUIVOCATION = 1
};

// One publicly exportable observation of a verified signed MPC envelope.
// Only the payload binding and word count are exposed; raw MPC/VSS words stay
// local to the observing process.
struct AuthenticatedMpcSignedEnvelopeObservation {
    bool available = false;
    AuthenticatedMpcMessageContext context{};
    uint32_t sender = 0;
    uint32_t receiver = 0;
    uint64_t payload_word_count = 0;
    Digest payload_binding{};
    std::array<uint8_t, 64> signature{};
    Digest registry_commitment{};
    Digest observation_binding{};
};

Digest compute_authenticated_mpc_signed_envelope_observation_binding(
    const AuthenticatedMpcSignedEnvelopeObservation& observation);
bool verify_authenticated_mpc_signed_envelope_observation(
    const AuthenticatedMpcSignedEnvelopeObservation& observation,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& expected_registry_anchor);

// Publicly attributable evidence requires two valid, conflicting signatures.
// A lone invalid signature is deliberately NOT sufficient to blame a sender:
// transport corruption could have produced it after the sender signed.
// Raw MPC/VSS payload contents are deliberately omitted from the public
// artifact; signatures authenticate only their canonical payload bindings.
struct AuthenticatedMpcEquivocationEvidence {
    bool available = false;
    AuthenticatedMpcAbortEvidenceKind kind =
        AuthenticatedMpcAbortEvidenceKind::UNKNOWN;
    AuthenticatedMpcMessageContext context{};
    uint32_t sender = 0;
    uint32_t receiver = 0;
    uint64_t first_payload_word_count = 0;
    Digest first_payload_binding{};
    std::array<uint8_t, 64> first_signature{};
    uint64_t second_payload_word_count = 0;
    Digest second_payload_binding{};
    std::array<uint8_t, 64> second_signature{};
    std::vector<std::array<uint8_t, 32>> public_keys;
    Digest registry_commitment{};
    Digest evidence_binding{};
};

Digest compute_authenticated_mpc_equivocation_evidence_binding(
    const AuthenticatedMpcEquivocationEvidence& evidence);
bool combine_authenticated_mpc_equivocation_observations(
    const AuthenticatedMpcSignedEnvelopeObservation& first,
    const AuthenticatedMpcSignedEnvelopeObservation& second,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& expected_registry_anchor,
    AuthenticatedMpcEquivocationEvidence* evidence);

struct AuthenticatedMpcObservationReconciliation {
    bool valid = false;
    bool equivocation_found = false;
    size_t input_count = 0;
    size_t accepted_count = 0;
    size_t rejected_count = 0;
    size_t duplicate_count = 0;
    // Backward-compatible alias for the canonical accepted observation count.
    size_t observation_count = 0;
    Digest observation_set_binding{};
    AuthenticatedMpcEquivocationEvidence evidence{};
};

Digest compute_authenticated_mpc_observation_set_binding(
    const std::vector<AuthenticatedMpcSignedEnvelopeObservation>& observations);
AuthenticatedMpcObservationReconciliation
reconcile_authenticated_mpc_observations(
    const std::vector<AuthenticatedMpcSignedEnvelopeObservation>& observations,
    const std::vector<std::array<uint8_t, 32>>& public_keys,
    const Digest& expected_registry_anchor);

// expected_registry_anchor must come from outside the disputed MPI session.
// Verification proves that the same registered sender signed two different
// payloads for the exact same logical context and receiver.
bool verify_authenticated_mpc_equivocation_evidence(
    const AuthenticatedMpcEquivocationEvidence& evidence,
    const Digest& expected_registry_anchor);

// Cryptographic wiring selftest. This tests signed-equivocation verification
// against the currently initialized registry; production trust still requires
// the caller to compare against an externally anchored registry commitment.
bool run_authenticated_mpc_equivocation_evidence_selftest(
    int rank, int world_size,
    AuthenticatedMpcEquivocationEvidence* verified_evidence = nullptr);

} // namespace pvia
