#include "FoldResidualComputationSelfTest.hpp"

#include "FoldResidualComputationBackend.hpp"
#include "FailClosedSecureAuditProvider.hpp"
#include "SecureAuditComposition.hpp"

namespace pvia {
namespace {
class MalformedResidualAuthenticator final
    : public PrivateResidualShareAuthenticator {
public:
    uint64_t SchemeId() const override { return 0x5445535450524f56ULL; }

    bool Authenticate(
        const PrivateResidualShare& share,
        PrivateResidualAuthenticationArtifact* artifact) const override {
        if (!artifact) return false;
        artifact->available = true;
        artifact->cryptographically_authenticated = true;
        artifact->scheme_id = SchemeId();
        artifact->computation_binding = share.computation_binding;
        artifact->source_state_id = share.source_state_id;
        artifact->source_state_owner = share.source_state_owner;
        artifact->source_state_digest = share.source_state_digest;
        artifact->source_state_authentication_scheme_id =
            share.source_state_authentication_scheme_id;
        artifact->source_state_authentication_binding =
            share.source_state_authentication_binding;
        artifact->public_aux_root = share.public_aux_root;
        artifact->operation_statement_binding =
            share.operation_statement_binding;
        artifact->proof_commitment = hash_words({1ULL});
        artifact->transcript_binding = hash_words({2ULL});
        artifact->binding = Digest{};
        return true;
    }
};
} // namespace

bool run_fold_residual_computation_selftest() {
    const std::vector<F> input = {
        F(1), F(2), F(3), F(4), F(5), F(6), F(7), F(8)};
    const F challenge = F(3);
    std::vector<F> expected;
    if (!recompute_fold_rs_output(input, challenge, &expected) ||
        expected.empty())
        return false;

    std::vector<F> actual = expected;
    actual[0] = actual[0] + F(1);

    AuditStateView state_view;
    state_view.id = 1;
    state_view.label.sid = 1;
    state_view.label.phase = Phase::FOLD;
    state_view.label.owner = 0;
    state_view.digest = hash_field_vector(input);
    PrivateStateMaterialStore states;
    states.RegisterMetadata(state_view);
    states.BindPrivateState(state_view, input);
    const Digest synthetic_state_auth = hash_words({0x5056494153544154ULL});
    if (!states.BindAuthentication(state_view, 0x5445535450524f56ULL,
                                   synthetic_state_auth) ||
        !states.BindAuthentication(state_view, 0x5445535450524f56ULL,
                                   synthetic_state_auth) ||
        states.BindAuthentication(state_view, 0x5445535450524f57ULL,
                                  synthetic_state_auth) ||
        states.BindAuthentication(state_view, 0x5445535450524f56ULL,
                                  hash_words({0xBADULL})) ||
        !states.VerifyDigest(state_view.id) ||
        !states.VerifyAuthentication(state_view.id))
        return false;

    FailClosedSecureAuditProvider fail_closed_provider;
    if (fail_closed_provider.BindPrivateStateAuthentication(
            state_view, 0x5445535450524f56ULL, synthetic_state_auth))
        return false;

    SecureAuditComponents empty_components;
    ComposedSecureAuditProvider composed_provider(empty_components, true);
    composed_provider.RegisterStateMetadata(state_view);
    composed_provider.BindPrivateState(state_view, input);
    SecureAuditBackend composed_backend(composed_provider);
    if (!composed_backend.OnBindPrivateStateAuthentication(
            state_view, 0x5445535450524f56ULL, synthetic_state_auth) ||
        composed_backend.OnBindPrivateStateAuthentication(
            state_view, 0x5445535450524f57ULL, synthetic_state_auth) ||
        composed_provider.Ready(SecureAuditRequirements{}))
        return false;
    AuditOperationView operation;
    operation.ref = OperationRef{0, 1};
    operation.label.sid = 1;
    operation.label.phase = Phase::FOLD;
    operation.label.round = 0;
    operation.label.owner = 0;
    operation.label.obligation = Obligation::FOLD;
    operation.label.object_id = 1;
    operation.relation = RelationKind::FOLDING;
    operation.kernel = AuditRelationKernel::FOLD_RS;
    operation.expected = hash_field_vector(expected);
    operation.actual = hash_field_vector(actual);
    operation.predecessor_root = hash_words(std::vector<u64>{});
    operation.predecessor_count = 0;
    operation.checkpoint = 1;
    operation.active = true;

    StateDependencyEvidence state_evidence;
    state_evidence.owner = 0;
    state_evidence.state_id = state_view.id;
    state_evidence.digest = state_view.digest;
    operation.state_dependency_root =
        compute_state_dependency_root({state_evidence});
    operation.state_dependency_count = 1;

    PublicAuxEvidence aux_evidence;
    aux_evidence.kind = AuditPublicAuxKind::FOLD_CHALLENGE;
    aux_evidence.digest = hash_field_vector({challenge});
    operation.public_aux_root = compute_public_aux_root({aux_evidence});
    operation.public_aux_count = 1;
    operation.relation_statement = compute_relation_statement(
        operation.label, operation.relation, operation.kernel,
        operation.expected, operation.predecessor_root,
        operation.predecessor_count, operation.state_dependency_root,
        operation.state_dependency_count, operation.public_aux_root,
        operation.public_aux_count);
    if (operation.relation_statement == Digest{}) return false;

    PrivateOperationMaterial material;
    material.operation = operation;
    material.has_field_input = true;
    material.has_field_output = true;
    material.field_input = expected;
    material.field_output = actual;
    material.state_dependencies.push_back(state_view.id);
    material.field_aux.push_back(
        {AuditPublicAuxKind::FOLD_CHALLENGE, {challenge}});
    material.public_aux_evidence.push_back(aux_evidence);

    KernelResidualContext context{operation, material, states};
    if (!validate_kernel_residual_material(context)) return false;

    PrivateResidualShareStore store;
    FoldResidualComputationBackend backend(store);
    const PrivateResidualHandle raw = backend.EvaluateKernel(context);
    if (!raw.available || raw.authenticated || raw.commitment == Digest{})
        return false;
    const PrivateResidualShare* share = store.Find(operation.ref);
    if (!share || !validate_private_residual_share(*share) ||
        share->authenticated || share->values.size() != expected.size() ||
        share->values[0] == F(0))
        return false;
    for (size_t i = 1; i < share->values.size(); ++i)
        if (share->values[i] != F(0)) return false;

    PrivateResidualShareStore malformed_store;
    MalformedResidualAuthenticator malformed_auth;
    FoldResidualComputationBackend malformed_backend(
        malformed_store, &malformed_auth);
    const PrivateResidualHandle malformed =
        malformed_backend.EvaluateKernel(context);
    const PrivateResidualShare* malformed_share =
        malformed_store.Find(operation.ref);
    if (!malformed.available || malformed.authenticated ||
        !malformed_share || malformed_share->authenticated ||
        malformed_share->authentication_binding != Digest{})
        return false;

    BackendKernelResidualEvaluator secure_gate(
        backend, {AuditRelationKernel::FOLD_RS});
    const PrivateResidualHandle gated = secure_gate.Evaluate(context);
    if (gated.available || gated.authenticated)
        return false;
    return true;
}

} // namespace pvia
