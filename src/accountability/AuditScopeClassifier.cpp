#include "AuditScopeClassifier.hpp"

#include <algorithm>

namespace pvia {

AuditScopeLane classify_audit_obligation(Obligation obligation) {
    switch (obligation) {
        case Obligation::SEND:
        case Obligation::RECEIVE:
        case Obligation::CONSUME:
            return AuditScopeLane::PUBLIC_TRANSFER;
        case Obligation::DERIVE:
        case Obligation::ASSEMBLE:
        case Obligation::AGGREGATE:
        case Obligation::PUBLISH:
        case Obligation::COMMIT:
        case Obligation::FOLD:
        case Obligation::OPEN:
            return AuditScopeLane::PRIVATE_RESIDUAL;
        default:
            return AuditScopeLane::UNSUPPORTED;
    }
}

AuditScopeLane classify_audit_relation(RelationKind relation) {
    switch (relation) {
        case RelationKind::MESSAGE_BINDING:
        case RelationKind::RECEIVE_CONSUME:
            return AuditScopeLane::PUBLIC_TRANSFER;
        case RelationKind::PRIVATE_DERIVATION:
        case RelationKind::ASSEMBLY:
        case RelationKind::AGGREGATION:
        case RelationKind::COMMITMENT:
        case RelationKind::FOLDING:
        case RelationKind::OPENING:
        case RelationKind::PUBLICATION:
            return AuditScopeLane::PRIVATE_RESIDUAL;
        default:
            return AuditScopeLane::UNSUPPORTED;
    }
}

namespace {
ObligationSet empty_child_scope(const ObligationSet& full) {
    ObligationSet out = full;
    out.obligations.clear();
    out.operations.clear();
    return out;
}
} // namespace
AuditScopePartition partition_audit_scope(
    const ObligationSet& full_scope,
    const std::function<AuditScopeLane(const OperationRef&)>& classify_operation) {
    AuditScopePartition partition;
    partition.private_scope = empty_child_scope(full_scope);
    partition.transfer_scope = empty_child_scope(full_scope);

    for (Obligation obligation : full_scope.obligations) {
        const AuditScopeLane lane = classify_audit_obligation(obligation);
        if (lane == AuditScopeLane::PRIVATE_RESIDUAL)
            partition.private_scope.obligations.push_back(obligation);
        else if (lane == AuditScopeLane::PUBLIC_TRANSFER)
            partition.transfer_scope.obligations.push_back(obligation);
    }

    if (!full_scope.private_operations.empty() ||
        !full_scope.transfer_operations.empty()) {
        partition.private_scope.operations = full_scope.private_operations;
        partition.transfer_scope.operations = full_scope.transfer_operations;
        bool complete = true;
        for (const OperationRef& ref : full_scope.operations) {
            const bool in_private = std::find(
                full_scope.private_operations.begin(),
                full_scope.private_operations.end(), ref) !=
                full_scope.private_operations.end();
            const bool in_transfer = std::find(
                full_scope.transfer_operations.begin(),
                full_scope.transfer_operations.end(), ref) !=
                full_scope.transfer_operations.end();
            if (!in_private && !in_transfer) complete = false;
        }
        partition.complete = complete;
        return partition;
    }

    bool complete = true;
    for (const OperationRef& ref : full_scope.operations) {
        const AuditScopeLane lane = classify_operation(ref);
        if (lane == AuditScopeLane::PRIVATE_RESIDUAL ||
            lane == AuditScopeLane::PRIVATE_AND_TRANSFER)
            partition.private_scope.operations.push_back(ref);
        if (lane == AuditScopeLane::PUBLIC_TRANSFER ||
            lane == AuditScopeLane::PRIVATE_AND_TRANSFER)
            partition.transfer_scope.operations.push_back(ref);
        if (lane == AuditScopeLane::UNSUPPORTED) complete = false;
    }

    partition.complete = complete;
    return partition;
}

} // namespace pvia
