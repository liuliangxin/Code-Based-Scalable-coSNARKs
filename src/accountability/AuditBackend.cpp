#include "AuditBackend.hpp"
#include "PublicJudge.hpp"

namespace pvia {

BatchCheckResult DebugAuditBackend::BatchCheck(const ObligationSet& scope) const {
    return runtime_.debug_batch_check(scope);
}

Violation DebugAuditBackend::Dispute(const ObligationSet& scope,
                                         const BatchCheckResult& batch) const {
    return runtime_.debug_dispute(scope, batch);
}

RecoverableAuditShare DebugAuditBackend::RecoverAudit(
    const Violation& violation) const {
    return runtime_.recover_debug_audit(violation);
}

BlameCertificate DebugAuditBackend::LiftBlame(
    const Violation& violation,
    const RecoverableAuditShare& audit) const {
    return runtime_.lift_debug_blame(violation, audit);
}

bool DebugAuditBackend::Judge(
    const BlameCertificate& certificate,
    uint64_t expected_session_id) const {
    return PublicJudge::VerifyDebug(certificate, expected_session_id);
}

} // namespace pvia
