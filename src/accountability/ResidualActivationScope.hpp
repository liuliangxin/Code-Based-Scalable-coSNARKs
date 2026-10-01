#pragma once

#include "AuditScopeClassifier.hpp"
#include "PrivateAuditMaterialStore.hpp"

namespace pvia {

// Build the canonical private-residual scope when all operation metadata is
// locally available. Public-transfer operations are validated but omitted.
bool build_private_residual_activation_scope(
    const AuditCheckpointView& checkpoint,
    const PrivateAuditMaterialStore& materials,
    ObligationSet* private_scope);

// Build the local-owner fragment used before failure handling. Metadata is
// required only for checkpoint operations owned by local_owner. The explicit
// session id lets ranks with no owned operation still enter the same collective.
bool build_local_private_residual_activation_scope(
    const AuditCheckpointView& checkpoint,
    const PrivateAuditMaterialStore& materials,
    uint32_t local_owner,
    uint64_t expected_session_id,
    ObligationSet* local_private_scope);

} // namespace pvia
