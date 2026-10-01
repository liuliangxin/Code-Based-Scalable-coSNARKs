#include "ResidualMpcMaliciousSecurity.hpp"
#include "AuthenticatedMpcAbortEvidence.hpp"

#include <cstring>
#include <vector>

namespace pvia {
namespace {

constexpr u64 RESIDUAL_MALICIOUS_CAP_DOMAIN =
    0x5056524d53454343ULL; // PVRMSECC
constexpr u64 RESIDUAL_MALICIOUS_ATTEST_DOMAIN =
    0x5056524d53454154ULL; // PVRMSEAT
constexpr u64 RESIDUAL_COMPOSED_ABORT_PROTOCOL_ID =
    0x5056524d43414231ULL; // PVRMCAB1
constexpr u64 RESIDUAL_COMPOSED_ABORT_IMPL_DOMAIN =
    0x5056524d4341494dULL; // PVRMCAIM

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

bool is_strong_level(RobustAuditSecurityLevel level) {
    return level == RobustAuditSecurityLevel::MALICIOUS_ABORT ||
           level == RobustAuditSecurityLevel::MALICIOUS_GOD;
}

} // namespace
Digest compute_residual_mpc_malicious_security_capability_binding(
    const ResidualMpcMaliciousSecurityCapabilities& c) {
    std::vector<u64> words = {
        RESIDUAL_MALICIOUS_CAP_DOMAIN,
        c.available ? 1ULL : 0ULL,
        c.protocol_id,
        static_cast<u64>(c.security_level),
        c.malicious_secure ? 1ULL : 0ULL,
        c.binds_residual_implementation ? 1ULL : 0ULL,
        c.binds_failure_before_activation ? 1ULL : 0ULL,
        c.publicly_identifiable_abort ? 1ULL : 0ULL,
        c.guaranteed_output_delivery ? 1ULL : 0ULL};
    append_digest(c.residual_implementation_binding, &words);
    append_digest(c.strong_consistency_capability_binding, &words);
    append_digest(c.identifiable_abort_capability_binding, &words);
    append_digest(c.delivery_capability_binding, &words);
    append_digest(c.implementation_binding, &words);
    return hash_words(words);
}

bool validate_residual_mpc_malicious_security_capabilities(
    const ResidualMpcMaliciousSecurityCapabilities& c) {
    if (!c.available || c.protocol_id == 0 || !is_strong_level(c.security_level) ||
        !c.malicious_secure || !c.binds_residual_implementation ||
        !c.binds_failure_before_activation)
        return false;
    if (c.residual_implementation_binding == Digest{} ||
        c.strong_consistency_capability_binding == Digest{} ||
        c.implementation_binding == Digest{})
        return false;
    if (c.publicly_identifiable_abort !=
        (c.identifiable_abort_capability_binding != Digest{}))
        return false;
    if (c.guaranteed_output_delivery !=
        (c.delivery_capability_binding != Digest{}))
        return false;
    if (!c.publicly_identifiable_abort) return false;
    if (c.security_level == RobustAuditSecurityLevel::MALICIOUS_ABORT) {
        if (c.guaranteed_output_delivery) return false;
    } else if (c.security_level == RobustAuditSecurityLevel::MALICIOUS_GOD) {
        if (!c.guaranteed_output_delivery) return false;
    }
    return c.capability_binding != Digest{} &&
        c.capability_binding ==
            compute_residual_mpc_malicious_security_capability_binding(c);
}

bool residual_mpc_malicious_security_satisfies(
    const ResidualMpcMaliciousSecurityCapabilities& c,
    RobustAuditSecurityLevel required_security) {
    if (!validate_residual_mpc_malicious_security_capabilities(c)) return false;
    switch (required_security) {
        case RobustAuditSecurityLevel::MALICIOUS_ABORT:
            return c.security_level == RobustAuditSecurityLevel::MALICIOUS_ABORT ||
                   c.security_level == RobustAuditSecurityLevel::MALICIOUS_GOD;
        case RobustAuditSecurityLevel::MALICIOUS_GOD:
            return c.security_level == RobustAuditSecurityLevel::MALICIOUS_GOD &&
                   c.guaranteed_output_delivery;
        default:
            return false;
    }
}

Digest compute_residual_mpc_security_attestation_binding(
    const ResidualMpcSecurityAttestation& a) {
    std::vector<u64> words = {
        RESIDUAL_MALICIOUS_ATTEST_DOMAIN,
        a.available ? 1ULL : 0ULL,
        a.sid,
        a.checkpoint,
        static_cast<u64>(a.security_level)};
    append_digest(a.scope_binding, &words);
    append_digest(a.residual_mpc_capability_binding, &words);
    append_digest(a.activation_binding, &words);
    append_digest(a.strong_consistency_capability_binding, &words);
    append_digest(a.identifiable_abort_capability_binding, &words);
    append_digest(a.delivery_capability_binding, &words);
    append_digest(a.security_capability_binding, &words);
    return hash_words(words);
}

bool validate_residual_mpc_security_attestation(
    const ObligationSet& scope,
    const ResidualMpcCapabilities& residual,
    const ResidualMpcMaliciousSecurityCapabilities& security,
    const ResidualMpcSecurityAttestation& a,
    RobustAuditSecurityLevel required_security) {
    if (!validate_residual_mpc_capabilities(residual) ||
        !residual_mpc_malicious_security_satisfies(
            security, required_security) ||
        !residual.activation_before_failure ||
        residual.implementation_binding == Digest{})
        return false;
    if (security.residual_implementation_binding !=
        residual.implementation_binding)
        return false;
    const AuthenticatedMpcAbortEvidenceCapabilities abort_capabilities =
        make_signed_equivocation_abort_evidence_capabilities(
            residual.authenticated_channel_capability_binding);
    if (!production_ready_authenticated_mpc_abort_evidence_capabilities(
            abort_capabilities) ||
        security.identifiable_abort_capability_binding !=
            abort_capabilities.capability_binding)
        return false;
    if (!a.available || a.sid != scope.session_id ||
        a.checkpoint != scope.checkpoint ||
        a.security_level != security.security_level ||
        a.scope_binding != compute_collective_scope_binding(scope))
        return false;
    if (a.residual_mpc_capability_binding != residual.capability_binding ||
        a.security_capability_binding != security.capability_binding)
        return false;
    if (a.activation_binding == Digest{} ||
        a.strong_consistency_capability_binding == Digest{} ||
        a.strong_consistency_capability_binding !=
            security.strong_consistency_capability_binding)
        return false;
    if (a.identifiable_abort_capability_binding !=
        security.identifiable_abort_capability_binding ||
        a.delivery_capability_binding != security.delivery_capability_binding)
        return false;
    if (a.attestation_binding == Digest{} ||
        a.attestation_binding !=
            compute_residual_mpc_security_attestation_binding(a))
        return false;
    return true;
}

ComposedResidualMpcMaliciousAbortSecurityProvider::
ComposedResidualMpcMaliciousAbortSecurityProvider(
    const Digest& residual_implementation_binding,
    const MultiplicationConsistencyProofBackend& consistency_backend,
    const Digest& authenticated_transport_capability_binding)
    : residual_implementation_binding_(residual_implementation_binding),
      consistency_backend_(consistency_backend),
      authenticated_transport_capability_binding_(
          authenticated_transport_capability_binding) {}

ResidualMpcMaliciousSecurityCapabilities
ComposedResidualMpcMaliciousAbortSecurityProvider::Capabilities() const {
    ResidualMpcMaliciousSecurityCapabilities c;
    const MultiplicationConsistencyCapabilities consistency =
        consistency_backend_.Capabilities();
    const AuthenticatedMpcAbortEvidenceCapabilities abort_capabilities =
        make_signed_equivocation_abort_evidence_capabilities(
            authenticated_transport_capability_binding_);
    if (residual_implementation_binding_ == Digest{} ||
        authenticated_transport_capability_binding_ == Digest{} ||
        !production_ready_multiplication_consistency_capabilities(
            consistency) ||
        !production_ready_authenticated_mpc_abort_evidence_capabilities(
            abort_capabilities))
        return c;

    c.available = true;
    c.protocol_id = RESIDUAL_COMPOSED_ABORT_PROTOCOL_ID;
    c.security_level = RobustAuditSecurityLevel::MALICIOUS_ABORT;
    c.malicious_secure = true;
    c.binds_residual_implementation = true;
    c.binds_failure_before_activation = true;
    c.publicly_identifiable_abort = true;
    c.guaranteed_output_delivery = false;
    c.residual_implementation_binding = residual_implementation_binding_;
    c.strong_consistency_capability_binding = consistency.capability_binding;
    c.identifiable_abort_capability_binding =
        abort_capabilities.capability_binding;
    c.delivery_capability_binding = Digest{};

    std::vector<u64> implementation_words = {
        RESIDUAL_COMPOSED_ABORT_IMPL_DOMAIN,
        RESIDUAL_COMPOSED_ABORT_PROTOCOL_ID};
    append_digest(residual_implementation_binding_, &implementation_words);
    append_digest(consistency.implementation_binding, &implementation_words);
    append_digest(consistency.capability_binding, &implementation_words);
    append_digest(abort_capabilities.implementation_binding,
                  &implementation_words);
    append_digest(abort_capabilities.capability_binding,
                  &implementation_words);
    append_digest(authenticated_transport_capability_binding_,
                  &implementation_words);
    c.implementation_binding = hash_words(implementation_words);
    c.capability_binding =
        compute_residual_mpc_malicious_security_capability_binding(c);
    if (!validate_residual_mpc_malicious_security_capabilities(c))
        return ResidualMpcMaliciousSecurityCapabilities{};
    return c;
}

ResidualMpcSecurityAttestation
ComposedResidualMpcMaliciousAbortSecurityProvider::AttestActivatedState(
    const ObligationSet& scope,
    const ResidualMpcCapabilities& residual,
    const Digest& activation_binding,
    const Digest& strong_consistency_capability_binding) const {
    ResidualMpcSecurityAttestation a;
    const ResidualMpcMaliciousSecurityCapabilities security = Capabilities();
    if (!validate_residual_mpc_capabilities(residual) ||
        !residual_mpc_malicious_security_satisfies(
            security, RobustAuditSecurityLevel::MALICIOUS_ABORT) ||
        !residual.activation_before_failure ||
        residual.implementation_binding != residual_implementation_binding_ ||
        residual.authenticated_channel_capability_binding !=
            authenticated_transport_capability_binding_ ||
        activation_binding == Digest{} ||
        strong_consistency_capability_binding !=
            security.strong_consistency_capability_binding)
        return a;

    a.available = true;
    a.sid = scope.session_id;
    a.checkpoint = scope.checkpoint;
    a.security_level = security.security_level;
    a.scope_binding = compute_collective_scope_binding(scope);
    a.residual_mpc_capability_binding = residual.capability_binding;
    a.activation_binding = activation_binding;
    a.strong_consistency_capability_binding =
        strong_consistency_capability_binding;
    a.identifiable_abort_capability_binding =
        security.identifiable_abort_capability_binding;
    a.delivery_capability_binding = security.delivery_capability_binding;
    a.security_capability_binding = security.capability_binding;
    a.attestation_binding =
        compute_residual_mpc_security_attestation_binding(a);
    if (!validate_residual_mpc_security_attestation(
            scope, residual, security, a,
            RobustAuditSecurityLevel::MALICIOUS_ABORT))
        return ResidualMpcSecurityAttestation{};
    return a;
}

bool ComposedResidualMpcMaliciousAbortSecurityProvider::VerifyAttestation(
    const ObligationSet& scope,
    const ResidualMpcCapabilities& residual,
    const ResidualMpcSecurityAttestation& attestation,
    RobustAuditSecurityLevel required_security) const {
    if (required_security != RobustAuditSecurityLevel::MALICIOUS_ABORT ||
        residual.implementation_binding != residual_implementation_binding_ ||
        residual.authenticated_channel_capability_binding !=
            authenticated_transport_capability_binding_)
        return false;
    const ResidualMpcMaliciousSecurityCapabilities security = Capabilities();
    const MultiplicationConsistencyCapabilities consistency =
        consistency_backend_.Capabilities();
    const AuthenticatedMpcAbortEvidenceCapabilities abort_capabilities =
        make_signed_equivocation_abort_evidence_capabilities(
            authenticated_transport_capability_binding_);
    if (!production_ready_multiplication_consistency_capabilities(
            consistency) ||
        consistency.capability_binding !=
            security.strong_consistency_capability_binding ||
        !production_ready_authenticated_mpc_abort_evidence_capabilities(
            abort_capabilities) ||
        abort_capabilities.capability_binding !=
            security.identifiable_abort_capability_binding)
        return false;
    return validate_residual_mpc_security_attestation(
        scope, residual, security, attestation, required_security);
}

ResidualMpcMaliciousSecurityCapabilities
FailClosedResidualMpcMaliciousSecurityProvider::Capabilities() const {
    return {};
}

ResidualMpcSecurityAttestation
FailClosedResidualMpcMaliciousSecurityProvider::AttestActivatedState(
    const ObligationSet&,
    const ResidualMpcCapabilities&,
    const Digest&,
    const Digest&) const {
    return {};
}
bool FailClosedResidualMpcMaliciousSecurityProvider::VerifyAttestation(
    const ObligationSet&,
    const ResidualMpcCapabilities&,
    const ResidualMpcSecurityAttestation&,
    RobustAuditSecurityLevel) const {
    return false;
}

bool run_residual_mpc_malicious_security_boundary_selftest() {
    ResidualMpcCapabilities residual;
    residual.available = true;
    residual.protocol_id = 0x52534d5345435250ULL; // RSMSECRP
    residual.security_level = RobustAuditSecurityLevel::REFERENCE_PASSIVE;
    residual.malicious_secure = false;
    residual.activation_before_failure = true;
    residual.authenticated_channels = true;
    residual.private_residual_sharing = true;
    residual.commit_before_challenge = true;
    residual.joint_unpredictable_challenge = true;
    residual.random_linear_batch_check = true;
    residual.masked_zero_test = true;
    residual.recursive_subset_localization = true;
    residual.publicly_identifiable_abort = false;
    residual.guaranteed_output_delivery = false;
    residual.authenticated_channel_capability_binding =
        hash_words({0x52534d5345434155ULL});
    residual.identifiable_abort_capability_binding = Digest{};
    residual.delivery_capability_binding = Digest{};
    residual.implementation_binding = hash_words({0x52534d534543494dULL});
    residual.capability_binding = compute_residual_mpc_capability_binding(residual);
    if (!validate_residual_mpc_capabilities(residual)) return false;

    ParticipantResidualCommitment participant;
    participant.owner = 0;
    participant.handle_count = 1;
    participant.descriptor_digest = hash_words({0x52534d5345434431ULL});
    participant.local_commitment_root = hash_words({0x52534d5345434c31ULL});
    participant.authentication_commitment = hash_words({0x52534d5345434131ULL});
    const std::vector<ParticipantResidualCommitment> participants = {participant};
    const Digest plain_root = compute_participant_commitment_root(participants);
    const Digest security_link = hash_words({0x52534d5345434c4bULL});
    const Digest secured_root = compute_collective_residual_commitment_root(
        participants, security_link);
    if (plain_root == Digest{} || secured_root == Digest{} ||
        secured_root == plain_root ||
        secured_root == compute_collective_residual_commitment_root(
            participants, hash_words({0x52534d5345434c32ULL})))
        return false;

    ResidualMpcMaliciousSecurityCapabilities security;
    security.available = true;
    security.protocol_id = 0x52534d5345435031ULL; // RSMSECP1
    security.security_level = RobustAuditSecurityLevel::MALICIOUS_ABORT;
    security.malicious_secure = true;
    security.binds_residual_implementation = true;
    security.binds_failure_before_activation = true;
    security.publicly_identifiable_abort = true;
    security.guaranteed_output_delivery = false;
    security.residual_implementation_binding = residual.implementation_binding;
    security.strong_consistency_capability_binding =
        hash_words({0x52534d534543434eULL});
    const auto selftest_abort_capabilities =
        make_signed_equivocation_abort_evidence_capabilities(
            residual.authenticated_channel_capability_binding);
    if (!production_ready_authenticated_mpc_abort_evidence_capabilities(
            selftest_abort_capabilities))
        return false;
    security.identifiable_abort_capability_binding =
        selftest_abort_capabilities.capability_binding;
    security.delivery_capability_binding = Digest{};
    security.implementation_binding = hash_words({0x52534d5345435349ULL});
    security.capability_binding =
        compute_residual_mpc_malicious_security_capability_binding(security);
    if (!validate_residual_mpc_malicious_security_capabilities(security) ||
        !residual_mpc_malicious_security_satisfies(
            security, RobustAuditSecurityLevel::MALICIOUS_ABORT) ||
        residual_mpc_malicious_security_satisfies(
            security, RobustAuditSecurityLevel::MALICIOUS_GOD))
        return false;

    ObligationSet scope;
    scope.session_id = 0x52534d5345435343ULL;
    scope.phase = Phase::FOLD;
    scope.round = 9;
    scope.generation = 1;
    scope.exact_round = true;
    scope.checkpoint = 0x5ec1;
    scope.checkpoint_root = hash_words({0x52534d534543524fULL});
    scope.obligations = {Obligation::FOLD};
    const OperationRef ref{0, 17};
    scope.operations = {ref};
    scope.private_operations = {ref};

    ResidualMpcSecurityAttestation attestation;
    attestation.available = true;
    attestation.sid = scope.session_id;
    attestation.checkpoint = scope.checkpoint;
    attestation.security_level = security.security_level;
    attestation.scope_binding = compute_collective_scope_binding(scope);
    attestation.residual_mpc_capability_binding = residual.capability_binding;
    attestation.activation_binding = hash_words({0x52534d5345434143ULL});
    attestation.strong_consistency_capability_binding =
        security.strong_consistency_capability_binding;
    attestation.identifiable_abort_capability_binding =
        security.identifiable_abort_capability_binding;
    attestation.delivery_capability_binding = security.delivery_capability_binding;
    attestation.security_capability_binding = security.capability_binding;
    attestation.attestation_binding =
        compute_residual_mpc_security_attestation_binding(attestation);
    if (!validate_residual_mpc_security_attestation(
            scope, residual, security, attestation,
            RobustAuditSecurityLevel::MALICIOUS_ABORT))
        return false;

    ResidualMpcSecurityAttestation missing_activation = attestation;
    missing_activation.activation_binding = Digest{};
    missing_activation.attestation_binding =
        compute_residual_mpc_security_attestation_binding(missing_activation);
    if (validate_residual_mpc_security_attestation(
            scope, residual, security, missing_activation,
            RobustAuditSecurityLevel::MALICIOUS_ABORT))
        return false;

    ResidualMpcMaliciousSecurityCapabilities detached = security;
    detached.residual_implementation_binding = hash_words({0x4445544143484544ULL});
    detached.capability_binding =
        compute_residual_mpc_malicious_security_capability_binding(detached);
    ResidualMpcSecurityAttestation detached_attestation = attestation;
    detached_attestation.security_capability_binding = detached.capability_binding;
    detached_attestation.attestation_binding =
        compute_residual_mpc_security_attestation_binding(detached_attestation);
    if (validate_residual_mpc_security_attestation(
            scope, residual, detached, detached_attestation,
            RobustAuditSecurityLevel::MALICIOUS_ABORT))
        return false;

    ResidualMpcMaliciousSecurityCapabilities detached_abort = security;
    detached_abort.identifiable_abort_capability_binding =
        hash_words({0x44455441424f5254ULL}); // DETABORT
    detached_abort.capability_binding =
        compute_residual_mpc_malicious_security_capability_binding(
            detached_abort);
    ResidualMpcSecurityAttestation detached_abort_attestation = attestation;
    detached_abort_attestation.identifiable_abort_capability_binding =
        detached_abort.identifiable_abort_capability_binding;
    detached_abort_attestation.security_capability_binding =
        detached_abort.capability_binding;
    detached_abort_attestation.attestation_binding =
        compute_residual_mpc_security_attestation_binding(
            detached_abort_attestation);
    if (validate_residual_mpc_security_attestation(
            scope, residual, detached_abort, detached_abort_attestation,
            RobustAuditSecurityLevel::MALICIOUS_ABORT))
        return false;

    ResidualMpcMaliciousSecurityCapabilities invalid_god = security;
    invalid_god.security_level = RobustAuditSecurityLevel::MALICIOUS_GOD;
    invalid_god.capability_binding =
        compute_residual_mpc_malicious_security_capability_binding(invalid_god);
    if (validate_residual_mpc_malicious_security_capabilities(invalid_god))
        return false;
    FailClosedResidualMpcMaliciousSecurityProvider fail_closed;
    if (validate_residual_mpc_malicious_security_capabilities(
            fail_closed.Capabilities()))
        return false;
    const ResidualMpcSecurityAttestation unavailable =
        fail_closed.AttestActivatedState(
            scope, residual, attestation.activation_binding,
            attestation.strong_consistency_capability_binding);
    if (unavailable.available ||
        fail_closed.VerifyAttestation(
            scope, residual, attestation,
            RobustAuditSecurityLevel::MALICIOUS_ABORT))
        return false;
    return true;
}

} // namespace pvia
