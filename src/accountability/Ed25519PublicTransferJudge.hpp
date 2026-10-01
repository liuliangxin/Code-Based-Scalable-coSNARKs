#pragma once

#include "Ed25519PublicTransferBlameProofBackend.hpp"

namespace pvia {

// Session-scoped public adjudicator for transparent PUBLIC_TRANSFER evidence.
// Verification is cryptographic only relative to the currently registered
// Ed25519 rank-key registry; MPI itself is not an authentication mechanism.
class Ed25519PublicTransferJudge {
public:
    static bool Verify(
        const BlameCertificate& certificate,
        uint64_t expected_session_id);

    static bool VerifyAnchored(
        const BlameCertificate& certificate,
        uint64_t expected_session_id,
        const Digest& expected_registry_anchor);

    static bool VerifyEncoded(
        const std::vector<u64>& encoded_certificate,
        uint64_t expected_session_id,
        const Digest& expected_registry_anchor);
};

} // namespace pvia
