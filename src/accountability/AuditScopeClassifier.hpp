#pragma once

#include "PVIA.hpp"

#include <functional>

namespace pvia {

enum class AuditScopeLane : uint32_t {
    UNSUPPORTED = 0,
    PRIVATE_RESIDUAL = 1,
    PUBLIC_TRANSFER = 2,
    PRIVATE_AND_TRANSFER = 3
};

struct AuditScopePartition {
    ObligationSet private_scope{};
    ObligationSet transfer_scope{};
    bool complete = false;
};

AuditScopeLane classify_audit_obligation(Obligation obligation);
AuditScopeLane classify_audit_relation(RelationKind relation);

AuditScopePartition partition_audit_scope(
    const ObligationSet& full_scope,
    const std::function<AuditScopeLane(const OperationRef&)>& classify_operation);

} // namespace pvia
