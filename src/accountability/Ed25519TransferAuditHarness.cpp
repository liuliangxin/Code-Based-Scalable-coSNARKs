#include "Ed25519TransferAuditHarness.hpp"
#include "PublicTransferEvidence.hpp"
#include "Ed25519PublicTransferBlameProofBackend.hpp"
#include "Ed25519PublicTransferJudge.hpp"
#include "TransferAuthentication.hpp"

#include <cstring>

#include <mpi.h>

#include <algorithm>
#include <array>
#include <iostream>
#include <tuple>
#include <vector>

namespace pvia {
namespace {

struct TransferDescriptor {
    uint64_t sid = 0;
    Phase phase = Phase::UNKNOWN;
    uint32_t round = 0;
    CheckpointId checkpoint = 0;
    OperationRef ref{};
};

bool descriptor_less(const TransferDescriptor& a,
                     const TransferDescriptor& b) {
    return std::tie(a.sid, a.phase, a.round, a.checkpoint,
                    a.ref.owner, a.ref.object_id) <
           std::tie(b.sid, b.phase, b.round, b.checkpoint,
                    b.ref.owner, b.ref.object_id);
}

bool descriptor_equal(const TransferDescriptor& a,
                      const TransferDescriptor& b) {
    return !descriptor_less(a, b) && !descriptor_less(b, a);
}

Digest digest_from_meta_words(const u64* words) {
    Digest digest;
    std::memcpy(digest.bytes.data(), words, digest.bytes.size());
    return digest;
}



bool run_synthetic_mismatch(
    const TransferDescriptor& seed, int rank, int world_size,
    const Ed25519PublicTransferCheckBackend& backend) {
    constexpr u64 domain = 0x53594e54484d4953ULL; // SYNTHMIS
    const u64 object_id = 0xf000000000000000ULL ^ seed.checkpoint;
    const OperationRef ref{0U, object_id};
    const std::vector<u64> registered = {domain, seed.checkpoint, 1ULL};
    const std::vector<u64> wire = {domain, seed.checkpoint, 2ULL};

    std::vector<u64> encoded(PUBLIC_TRANSFER_OBSERVATION_WORDS, 0);
    int local_prepare_ok = 1;
    if (rank == 0) {
        auto meta = Runtime::instance().make_direct_meta(
            seed.phase, seed.round, Obligation::SEND, object_id, registered, false);
        meta[META_CHECKPOINT_INDEX] = seed.checkpoint;
        if (!Runtime::instance().seal_transfer_meta(meta, wire))
            local_prepare_ok = 0;

        PublicTransferObservation observation;
        observation.valid = true;
        observation.ref = ref;
        observation.source_label.sid = seed.sid;
        observation.source_label.phase = seed.phase;
        observation.source_label.round = seed.round;
        observation.source_label.owner = 0;
        observation.source_label.obligation = Obligation::SEND;
        observation.source_label.object_id = object_id;
        observation.transfer_label = observation.source_label;
        observation.checkpoint = seed.checkpoint;
        observation.observer_rank = 0;
        observation.predecessor_root = digest_from_meta_words(
            &meta[META_PREDECESSOR_ROOT_OFFSET]);
        observation.predecessor_count = static_cast<uint32_t>(
            meta[META_PREDECESSOR_COUNT_INDEX]);

        observation.state_dependency_root = digest_from_meta_words(
            &meta[META_STATE_DEP_ROOT_OFFSET]);
        observation.state_dependency_count = static_cast<uint32_t>(
            meta[META_STATE_DEP_COUNT_INDEX]);
        observation.public_aux_root = digest_from_meta_words(
            &meta[META_PUBLIC_AUX_ROOT_OFFSET]);
        observation.public_aux_count = static_cast<uint32_t>(
            meta[META_PUBLIC_AUX_COUNT_INDEX]);
        observation.registered_digest = hash_words(registered);
        observation.payload_digest = hash_words(wire);
        observation.operation_statement_binding = compute_relation_statement(
            observation.transfer_label, RelationKind::MESSAGE_BINDING,
            AuditRelationKernel::UNKNOWN, observation.registered_digest,
            observation.predecessor_root, observation.predecessor_count,
            observation.state_dependency_root, observation.state_dependency_count,
            observation.public_aux_root, observation.public_aux_count);

        observation.metadata_binding = hash_words(
            std::vector<u64>(meta.begin(), meta.end()));
        observation.authenticated_metadata = meta;
        observation.remote_observation = false;
        if (!validate_public_transfer_observation(observation))
            local_prepare_ok = 0;
        else
            encoded = encode_public_transfer_observation(observation);
    }
    int prepare_ok = 0;
    MPI_Allreduce(&local_prepare_ok, &prepare_ok, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    if (!prepare_ok) return false;
    MPI_Bcast(encoded.data(), static_cast<int>(encoded.size()), MPI_UINT64_T,
              0, MPI_COMM_WORLD);
    PublicTransferObservation observation;
    if (!decode_public_transfer_observation(encoded, &observation)) return false;

    ObligationSet scope;
    scope.session_id = seed.sid;
    scope.phase = seed.phase;
    scope.round = seed.round;
    scope.exact_round = true;
    scope.checkpoint = seed.checkpoint;
    scope.checkpoint_root = hash_words(std::vector<u64>{
        domain, seed.sid, static_cast<u64>(seed.phase),
        seed.round, seed.checkpoint});
    scope.obligations.push_back(Obligation::SEND);
    scope.operations.push_back(ref);
    scope.transfer_operations.push_back(ref);

    const std::vector<PublicTransferObservation> local{observation};
    const PublicTransferCheckResult check = backend.Check(
        scope, local, rank, world_size);
    if (!validate_public_transfer_check_result(scope, check) || check.ok ||
        check.checked_operations != 1 || check.mismatches != 1)
        return false;

    const CollectiveDisputeResult dispute = backend.Dispute(
        scope, check, local, rank, world_size);
    if (!validate_public_transfer_dispute_result(scope, check, dispute) ||
        !public_transfer_observation_supports_dispute(observation, dispute))
        return false;
    const Violation violation = materialize_collective_violation(dispute);
    if (!violation.valid || violation.dispute_binding == Digest{}) return false;
    const PublicTransferEvidence evidence = make_public_transfer_evidence(
        violation, scope, check, dispute, observation);
    if (!validate_public_transfer_evidence(
            violation, scope, check, dispute, observation, evidence) ||
        !validate_public_transfer_evidence_claim(evidence))
        return false;

    RecoverableAuditShare audit;
    audit.valid = true;
    audit.debug_only = false;
    audit.evidence_kind = AuditEvidenceKind::PUBLIC_TRANSFER;
    audit.label = violation.label;
    audit.relation = violation.relation;
    audit.kernel = violation.kernel;
    audit.expected = violation.expected;
    audit.actual = violation.actual;
    audit.residual_commitment = violation.residual_commitment;
    audit.operation_statement_binding = violation.operation_statement_binding;
    audit.dispute_binding = violation.dispute_binding;
    audit.predecessor_root = Digest{};
    audit.checkpoint_root = evidence.checkpoint_root;
    audit.witness_digest = evidence.evidence_binding;

    const PublicBlameStatement statement = make_public_blame_statement(
        violation, audit, evidence);
    if (statement.statement_binding == Digest{}) return false;

    Ed25519PublicTransferBlameProofBackend proof_backend;
    BackendPublicTransferBlameProofEngine proof_engine(proof_backend);
    const PublicBlameProofArtifact proof = proof_engine.Prove(
        statement, evidence);
    if (!validate_public_blame_proof_artifact(statement, proof) ||
        !proof_engine.Verify(statement, proof))
        return false;

    BlameCertificate cert;
    cert.valid = true;
    cert.debug_only = false;
    cert.evidence_kind = AuditEvidenceKind::PUBLIC_TRANSFER;
    cert.sid = violation.label.sid;
    cert.accused = violation.responsible_rank;
    cert.label = violation.label;
    cert.checkpoint = violation.checkpoint;
    cert.relation = violation.relation;
    cert.kernel = violation.kernel;
    cert.expected = violation.expected;
    cert.actual = violation.actual;
    cert.residual_commitment = violation.residual_commitment;
    cert.operation_statement_binding = violation.operation_statement_binding;
    cert.dispute_binding = violation.dispute_binding;
    cert.predecessor_root = audit.predecessor_root;
    cert.checkpoint_root = audit.checkpoint_root;
    cert.predecessor_evidence_complete = false;
    cert.audit_witness_digest = audit.witness_digest;
    cert.blame_statement_binding = statement.statement_binding;
    cert.public_proof_system_id = proof.proof_system_id;
    cert.public_proof_commitment = proof.proof_commitment;
    cert.public_proof_transcript_binding = proof.transcript_binding;
    cert.public_proof_words = proof.proof_words;
    cert.transcript_digest = proof.transcript_binding;
    cert.proof_digest = proof.proof_commitment;
    if (!Ed25519PublicTransferJudge::Verify(cert, cert.sid)) return false;
    if (Ed25519PublicTransferJudge::Verify(cert, cert.sid + 1)) return false;

    BlameCertificate tampered_cert = cert;
    tampered_cert.actual.bytes[0] ^= 1U;
    tampered_cert.residual_commitment = compute_residual_commitment(
        tampered_cert.label, tampered_cert.relation, tampered_cert.kernel,
        tampered_cert.expected, tampered_cert.actual);
    if (Ed25519PublicTransferJudge::Verify(tampered_cert, cert.sid))
        return false;

    PublicBlameProofArtifact tampered = proof;
    if (tampered.proof_words.empty()) return false;
    tampered.proof_words.back() ^= 1ULL;
    tampered.proof_commitment = compute_public_blame_proof_commitment(tampered);
    if (proof_engine.Verify(statement, tampered)) return false;

    auto& auth = Ed25519TransferAuthenticator::instance();
    const Digest registry_anchor = auth.RegistryCommitment();
    if (registry_anchor == Digest{}) return false;
    Digest wrong_anchor = registry_anchor;
    wrong_anchor.bytes[0] ^= 1U;
    auth.Reset();
    if (Ed25519PublicTransferJudge::Verify(cert, cert.sid)) return false;
    if (!Ed25519PublicTransferJudge::VerifyAnchored(
            cert, cert.sid, registry_anchor))
        return false;
    if (Ed25519PublicTransferJudge::VerifyAnchored(
            cert, cert.sid, wrong_anchor))
        return false;
    const bool final_ok = evidence.evidence_binding != Digest{};
    if (rank == 0 && final_ok) {
        std::cout
            << "[PVIA][transfer-no-framing-selftest]"
            << " valid-certificate=ACCEPT"
            << " wrong-session=REJECTED"
            << " certificate-tamper=REJECTED"
            << " proof-tamper=REJECTED"
            << " reset-without-anchor=REJECTED"
            << " wrong-anchor=REJECTED"
            << " result=PASS"
            << "\n";
    }
    return final_ok;
}

} // namespace

bool run_ed25519_transfer_no_framing_selftest(
    int rank, int world_size) {
    if (world_size < 2 || rank < 0 || rank >= world_size)
        return false;
    TransferDescriptor seed;
    seed.sid = Runtime::instance().session_id();
    seed.phase = Phase::FOLD;
    seed.round = 19U;
    seed.checkpoint =
        (static_cast<uint64_t>(seed.phase) << 56) |
        (static_cast<uint64_t>(seed.round) << 24) |
        1ULL;
    Ed25519PublicTransferCheckBackend backend;
    const bool local_ok =
        run_synthetic_mismatch(seed, rank, world_size, backend);
    int local = local_ok ? 1 : 0;
    int global = 0;
    MPI_Allreduce(
        &local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (rank == 0) {
        std::cout
            << "[PVIA][transfer-no-framing-entry]"
            << " result=" << (global ? "PASS" : "FAIL")
            << "\n";
    }
    return global != 0;
}

void Ed25519TransferAuditHarness::OnObservePublicTransfer(
    const PublicTransferObservation& observation) {
    if (!validate_public_transfer_observation(observation)) return;
    observations_.push_back(observation);
}

BatchCheckResult Ed25519TransferAuditHarness::BatchCheck(
    const ObligationSet& scope) const {
    BatchCheckResult result;
    result.checkpoint = scope.checkpoint;
    return result;
}

Violation Ed25519TransferAuditHarness::Dispute(
    const ObligationSet&, const BatchCheckResult&) const {
    return Violation{};
}

RecoverableAuditShare Ed25519TransferAuditHarness::RecoverAudit(
    const Violation&) const {
    return RecoverableAuditShare{};
}

BlameCertificate Ed25519TransferAuditHarness::LiftBlame(
    const Violation&, const RecoverableAuditShare&) const {
    return BlameCertificate{};
}

bool Ed25519TransferAuditHarness::Judge(
    const BlameCertificate&, uint64_t) const {
    return false;
}
bool Ed25519TransferAuditHarness::RunSelfCheck(
    int rank, int world_size) const {
    int comm_rank = -1;
    int comm_size = 0;
    MPI_Comm_rank(MPI_COMM_WORLD, &comm_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &comm_size);
    if (rank != comm_rank || world_size != comm_size || world_size <= 0)
        return false;

    std::vector<TransferDescriptor> local_descriptors;
    local_descriptors.reserve(observations_.size());
    for (const auto& observation : observations_) {
        if (!validate_public_transfer_observation(observation)) continue;
        TransferDescriptor d;
        d.sid = observation.transfer_label.sid;
        d.phase = observation.transfer_label.phase;
        d.round = observation.transfer_label.round;
        d.checkpoint = observation.checkpoint;
        d.ref = observation.ref;
        local_descriptors.push_back(d);
    }
    std::sort(local_descriptors.begin(), local_descriptors.end(),
              descriptor_less);
    local_descriptors.erase(
        std::unique(local_descriptors.begin(), local_descriptors.end(),
                    descriptor_equal),
        local_descriptors.end());
    std::vector<u64> local_words;
    local_words.reserve(local_descriptors.size() * 6);
    for (const auto& d : local_descriptors) {
        local_words.push_back(d.sid);
        local_words.push_back(static_cast<u64>(d.phase));
        local_words.push_back(d.round);
        local_words.push_back(d.checkpoint);
        local_words.push_back(d.ref.owner);
        local_words.push_back(d.ref.object_id);
    }

    const int local_count = static_cast<int>(local_words.size());
    std::vector<int> counts(static_cast<size_t>(world_size), 0);
    MPI_Allgather(&local_count, 1, MPI_INT,
                  counts.data(), 1, MPI_INT, MPI_COMM_WORLD);
    std::vector<int> displacements(static_cast<size_t>(world_size), 0);
    int total_words = 0;
    for (int i = 0; i < world_size; ++i) {
        displacements[static_cast<size_t>(i)] = total_words;
        total_words += counts[static_cast<size_t>(i)];
    }
    std::vector<u64> all_words(static_cast<size_t>(total_words), 0);
    MPI_Allgatherv(local_words.data(), local_count, MPI_UINT64_T,
                   all_words.data(), counts.data(), displacements.data(),
                   MPI_UINT64_T, MPI_COMM_WORLD);
    if (all_words.size() % 6 != 0) return false;
    std::vector<TransferDescriptor> descriptors;
    descriptors.reserve(all_words.size() / 6);
    for (size_t i = 0; i < all_words.size(); i += 6) {
        TransferDescriptor d;
        d.sid = all_words[i];
        d.phase = static_cast<Phase>(static_cast<uint32_t>(all_words[i + 1]));
        d.round = static_cast<uint32_t>(all_words[i + 2]);
        d.checkpoint = all_words[i + 3];
        d.ref.owner = static_cast<uint32_t>(all_words[i + 4]);
        d.ref.object_id = all_words[i + 5];
        descriptors.push_back(d);
    }
    std::sort(descriptors.begin(), descriptors.end(), descriptor_less);
    descriptors.erase(
        std::unique(descriptors.begin(), descriptors.end(), descriptor_equal),
        descriptors.end());
    if (descriptors.empty()) return false;

    size_t batches = 0;
    size_t checked_operations = 0;
    size_t mismatches = 0;
    size_t disputes = 0;
    bool success = true;
    size_t begin = 0;
    while (begin < descriptors.size()) {
        size_t end = begin + 1;
        while (end < descriptors.size() &&
               descriptors[end].sid == descriptors[begin].sid &&
               descriptors[end].phase == descriptors[begin].phase &&
               descriptors[end].round == descriptors[begin].round &&
               descriptors[end].checkpoint == descriptors[begin].checkpoint)
            ++end;

        ObligationSet scope;
        scope.session_id = descriptors[begin].sid;
        scope.phase = descriptors[begin].phase;
        scope.round = descriptors[begin].round;
        scope.exact_round = true;
        scope.checkpoint = descriptors[begin].checkpoint;
        scope.obligations.push_back(Obligation::SEND);
        for (size_t i = begin; i < end; ++i)
            scope.operations.push_back(descriptors[i].ref);
        scope.transfer_operations = scope.operations;

        const PublicTransferCheckResult result = transfer_backend_.Check(
            scope, observations_, rank, world_size);
        if (!validate_public_transfer_check_result(scope, result)) {
            success = false;
        } else {
            ++batches;
            checked_operations += result.checked_operations;
            mismatches += result.mismatches;
            if (!result.ok) {
                const CollectiveDisputeResult dispute = transfer_backend_.Dispute(
                    scope, result, observations_, rank, world_size);
                if (!validate_public_transfer_dispute_result(
                        scope, result, dispute))
                    success = false;
                else
                    ++disputes;
            }
        }
        begin = end;
    }
    const bool synthetic_mismatch = run_synthetic_mismatch(
        descriptors.front(), rank, world_size, transfer_backend_);
    success = success && synthetic_mismatch;
    int local_success = success ? 1 : 0;
    int global_success = 0;
    MPI_Allreduce(&local_success, &global_success, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    if (rank == 0) {
        std::cout << "[PVIA][transfer-selftest] batches=" << batches
                  << " operations=" << checked_operations
                  << " mismatches=" << mismatches
                  << " disputes=" << disputes
                  << " synthetic-mismatch=" << (synthetic_mismatch ? "yes" : "no")
                  << " authenticated=" << (global_success ? "yes" : "no")
                  << "\n";
    }
    return global_success != 0;
}

} // namespace pvia
