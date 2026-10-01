#pragma once

#include "RobustAuditSession.hpp"

#include <string>
#include <vector>

namespace pvia {

// Self-contained public abort certificate. Raw MPC/VSS payload words are
// intentionally absent: the nested equivocation artifact carries only payload
// bindings, signatures, and the public-key registry.
struct RobustAuditAbortCertificate {
    AuditCheckpointView checkpoint{};
    RobustAuditCapabilities capabilities{};
    bool has_activation = false;
    RobustAuditActivation activation{};
    RobustAuditAbortOutput output{};
};

// External trust is mandatory: expected_registry_anchor must come from outside
// the disputed session/certificate.
bool verify_robust_audit_abort_certificate(
    const RobustAuditAbortCertificate& certificate,
    const Digest& expected_registry_anchor);

// Canonical word encoding. Decode validates internal hashes/signatures against
// the anchor claimed inside the certificate, but does not establish trust in
// that anchor; callers must still invoke verify_robust_audit_abort_certificate
// with an externally trusted anchor.
std::vector<u64> encode_robust_audit_abort_certificate(
    const RobustAuditAbortCertificate& certificate);
bool decode_robust_audit_abort_certificate(
    const std::vector<u64>& words,
    RobustAuditAbortCertificate* certificate);
bool verify_encoded_robust_audit_abort_certificate(
    const std::vector<u64>& words,
    const Digest& expected_registry_anchor);

bool write_robust_audit_abort_certificate_file(
    const std::string& path,
    const RobustAuditAbortCertificate& certificate);
bool read_robust_audit_abort_certificate_file(
    const std::string& path,
    std::vector<u64>* encoded_certificate);
bool parse_robust_audit_registry_anchor_hex(
    const std::string& text, Digest* anchor);

} // namespace pvia
