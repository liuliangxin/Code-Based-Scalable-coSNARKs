#include "ResidualActivationScope.hpp"

#include <algorithm>

namespace pvia {
namespace {

bool ref_matches_label(const OperationRef& ref, const Label& label) {
    return ref.owner == label.owner && ref.object_id == label.object_id;
}

void append_unique_obligation(
    Obligation obligation, std::vector<Obligation>* obligations) {
    if (!obligations) return;
    if (std::find(obligations->begin(), obligations->end(), obligation) ==
        obligations->end())
        obligations->push_back(obligation);
}

bool lane_matches(
    AuditScopeLane relation_lane, AuditScopeLane obligation_lane) {
    return relation_lane != AuditScopeLane::UNSUPPORTED &&
           relation_lane == obligation_lane;
}

} // namespace
bool build_private_residual_activation_scope(
    const AuditCheckpointView& checkpoint,
    const PrivateAuditMaterialStore& materials,
    ObligationSet* private_scope) {
    if (!private_scope) return false;
    *private_scope = ObligationSet{};
    if (!checkpoint.sealed || checkpoint.id == 0 ||
        checkpoint.phase == Phase::UNKNOWN || checkpoint.root == Digest{} ||
        checkpoint.operations.empty())
        return false;

    ObligationSet full;
    full.phase = checkpoint.phase;
    full.round = checkpoint.round;
    full.generation = checkpoint.generation;
    full.exact_round = true;
    full.checkpoint = checkpoint.id;
    full.checkpoint_root = checkpoint.root;
    full.operations = checkpoint.operations;

    uint64_t session_id = 0;
    for (const OperationRef& ref : checkpoint.operations) {
        const PrivateOperationMaterial* material = materials.Find(ref);
        if (!material) return false;
        const AuditOperationView& operation = material->operation;
        if (operation.ref != ref || !ref_matches_label(ref, operation.label) ||
            operation.label.sid == 0 ||
            operation.label.phase != checkpoint.phase ||
            operation.label.round != checkpoint.round ||
            operation.checkpoint != checkpoint.id)
            return false;
        const AuditScopeLane relation_lane =
            classify_audit_relation(operation.relation);
        const AuditScopeLane obligation_lane =
            classify_audit_obligation(operation.label.obligation);
        if (!lane_matches(relation_lane, obligation_lane)) return false;
        if (relation_lane == AuditScopeLane::PRIVATE_RESIDUAL &&
            !material->finalized)
            return false;
        if (session_id == 0) session_id = operation.label.sid;
        if (session_id != operation.label.sid) return false;
        append_unique_obligation(
            operation.label.obligation, &full.obligations);
    }
    if (session_id == 0) return false;
    full.session_id = session_id;

    const AuditScopePartition partition = partition_audit_scope(
        full, [&materials](const OperationRef& ref) {
            const PrivateOperationMaterial* material = materials.Find(ref);
            if (!material) return AuditScopeLane::UNSUPPORTED;
            return classify_audit_relation(material->operation.relation);
        });
    if (!partition.complete) return false;

    *private_scope = partition.private_scope;
    private_scope->private_operations = private_scope->operations;
    private_scope->transfer_operations.clear();
    return true;
}


bool build_local_private_residual_activation_scope(
    const AuditCheckpointView& checkpoint,
    const PrivateAuditMaterialStore& materials,
    uint32_t local_owner,
    uint64_t expected_session_id,
    ObligationSet* local_private_scope) {
    if (!local_private_scope || expected_session_id == 0) return false;
    *local_private_scope = ObligationSet{};
    if (!checkpoint.sealed || checkpoint.id == 0 ||
        checkpoint.phase == Phase::UNKNOWN || checkpoint.root == Digest{} ||
        checkpoint.operations.empty())
        return false;

    ObligationSet local;
    local.phase = checkpoint.phase;
    local.round = checkpoint.round;
    local.generation = checkpoint.generation;
    local.exact_round = true;
    local.checkpoint = checkpoint.id;
    local.checkpoint_root = checkpoint.root;

    uint64_t session_id = expected_session_id;
    size_t owned_count = 0;
    std::vector<OperationRef> owned_refs;
    for (const OperationRef& ref : checkpoint.operations) {
        if (ref.owner != local_owner) continue;
        ++owned_count;
        owned_refs.push_back(ref);
        const PrivateOperationMaterial* material = materials.Find(ref);
        if (!material || ref.object_id == 0) return false;
        const AuditOperationView& operation = material->operation;
        if (operation.ref != ref || !ref_matches_label(ref, operation.label) ||
            operation.label.sid == 0 ||
            operation.label.phase != checkpoint.phase ||
            operation.label.round != checkpoint.round ||
            operation.checkpoint != checkpoint.id)
            return false;
        const AuditScopeLane relation_lane =
            classify_audit_relation(operation.relation);
        const AuditScopeLane obligation_lane =
            classify_audit_obligation(operation.label.obligation);
        if (!lane_matches(relation_lane, obligation_lane)) return false;
        if (session_id != operation.label.sid) return false;
        if (relation_lane == AuditScopeLane::PRIVATE_RESIDUAL) {
            if (!material->finalized) return false;
            local.operations.push_back(ref);
            local.private_operations.push_back(ref);
            append_unique_obligation(
                operation.label.obligation, &local.obligations);
        }
    }
    (void)owned_count;

    auto ref_less = [](const OperationRef& lhs, const OperationRef& rhs) {
        return lhs.owner != rhs.owner ? lhs.owner < rhs.owner
                                      : lhs.object_id < rhs.object_id;
    };
    std::sort(owned_refs.begin(), owned_refs.end(), ref_less);
    if (std::adjacent_find(owned_refs.begin(), owned_refs.end()) !=
        owned_refs.end())
        return false;
    std::sort(local.operations.begin(), local.operations.end(), ref_less);
    local.private_operations = local.operations;
    std::sort(local.obligations.begin(), local.obligations.end(),
        [](Obligation lhs, Obligation rhs) {
            return static_cast<uint32_t>(lhs) < static_cast<uint32_t>(rhs);
        });
    local.session_id = session_id;
    *local_private_scope = std::move(local);
    return true;
}

} // namespace pvia
