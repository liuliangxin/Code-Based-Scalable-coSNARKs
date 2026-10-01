#pragma once

#include "AuditScopeClassifier.hpp"
#include "CollectiveResidualEngine.hpp"
#include "PublicTransferCheckEngine.hpp"

namespace pvia {

struct HybridAuditBatchComponents {
    bool private_present = false;
    bool transfer_present = false;
    BatchCheckResult private_result{};
    PublicTransferCheckResult transfer_result{};
};

BatchCheckResult make_hybrid_audit_batch_envelope(
    const ObligationSet& full_scope,
    const AuditScopePartition& partition,
    const HybridAuditBatchComponents& components,
    int world_size);

bool validate_hybrid_audit_batch_envelope(
    const ObligationSet& full_scope,
    const AuditScopePartition& partition,
    const HybridAuditBatchComponents& components,
    const BatchCheckResult& envelope,
    int world_size);

} // namespace pvia
