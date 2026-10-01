#include "Ed25519TransferSecureRuntime.hpp"
#include "TransferAuthentication.hpp"
#include "Ed25519PublicTransferJudge.hpp"
#include "PublicTransferCertificateCodec.hpp"

#include <mpi.h>
#include <iostream>
#include <vector>

namespace pvia {
namespace {

SecureAuditComponents make_transfer_components(
    const PublicTransferCheckEngine* check_engine,
    const PublicTransferBlameProofEngine* proof_engine) {
    SecureAuditComponents components;
    components.transfer_engine = check_engine;
    components.transfer_blame_proof_engine = proof_engine;
    return components;
}

SecureAuditRequirements make_transfer_requirements() {
    SecureAuditRequirements requirements;
    requirements.private_lane = false;
    requirements.transfer_lane = true;
    requirements.required_kernels.clear();
    return requirements;
}

} // namespace

Ed25519TransferSecureRuntime::Ed25519TransferSecureRuntime()
    : check_engine_(check_backend_),
      proof_engine_(proof_backend_),
      bundle_(make_transfer_components(&check_engine_, &proof_engine_),
              make_transfer_requirements()) {}

bool Ed25519TransferSecureRuntime::SessionAuthenticationReady(
    bool require_external_anchor) const {
    const auto& auth = Ed25519TransferAuthenticator::instance();
    int local_ok = auth.ready() && auth.RegistryCommitment() != Digest{} &&
        (!require_external_anchor || auth.ExternalRegistryAnchorVerified())
        ? 1 : 0;
    int global_ok = 0;
    MPI_Allreduce(&local_ok, &global_ok, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    return global_ok != 0;
}

} // namespace pvia

bool pvia::Ed25519TransferSecureRuntime::RunFailureHandlerSelfTest(
    pvia::Runtime& runtime, int rank, int world_size) {
    if (!ready() || runtime.audit_backend() != &backend() ||
        !runtime.enabled() || world_size <= 0)
        return false;

    uint64_t selected[3] = {0, 0, 0};
    if (rank == 0) {
        const pvia::Phase phases[] = {
            pvia::Phase::PCS, pvia::Phase::DISTRIBUTED_SUMCHECK,
            pvia::Phase::ENCODING, pvia::Phase::ORACLE,
            pvia::Phase::FOLD, pvia::Phase::OPENING,
            pvia::Phase::COSUMCHECK_BATCH,
            pvia::Phase::COSUMCHECK_QUADRATIC,
            pvia::Phase::COSUMCHECK_ZERO};
        for (pvia::Phase candidate : phases) {
            for (uint32_t r = 0; r < 256; ++r) {
                const pvia::CheckpointId checkpoint =
                    runtime.checkpoint_id(candidate, r);
                if (checkpoint == 0) continue;
                selected[0] = static_cast<uint64_t>(candidate);
                selected[1] = r;
                selected[2] = checkpoint;
                break;
            }
            if (selected[2] != 0) break;
        }
    }
    MPI_Bcast(selected, 3, MPI_UINT64_T, 0, MPI_COMM_WORLD);
    if (selected[2] == 0) return false;

    const pvia::Phase phase = static_cast<pvia::Phase>(
        static_cast<uint32_t>(selected[0]));
    const uint32_t round = static_cast<uint32_t>(selected[1]);
    pvia::CheckpointId checkpoint = 0;

    int local_prepare_ok = 1;
    if (rank == 0) {
        constexpr uint64_t domain = 0x5345435452465448ULL; // SECTRFTH
        const std::vector<u64> registered = {
            domain, selected[2], 1ULL};
        const std::vector<u64> wire = {
            domain, selected[2], 2ULL};
        const pvia::RecordId id = runtime.register_word_operation(
            phase, round, pvia::Obligation::SEND, registered, {});
        if (id == 0) {
            local_prepare_ok = 0;
        } else {
            runtime.activate_words(id, registered);
            auto meta = runtime.make_pending_meta(registered, false);
            checkpoint = meta[pvia::META_CHECKPOINT_INDEX];
            if (checkpoint == 0 ||
                !runtime.seal_transfer_meta(meta, wire)) {
                local_prepare_ok = 0;
            } else {
                runtime.observe_outgoing_transfer(meta, wire);
                runtime.consume_pending();
            }
        }
    }
    MPI_Bcast(&checkpoint, 1, MPI_UINT64_T, 0, MPI_COMM_WORLD);
    int prepare_ok = 0;
    MPI_Allreduce(&local_prepare_ok, &prepare_ok, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    if (!prepare_ok) return false;
    MPI_Barrier(MPI_COMM_WORLD);
    const bool handled = runtime.handle_global_failure_with_backend(
        "final_codeword_secure_transfer_selftest", phase, round, backend());
    const pvia::BlameCertificate& cert = runtime.latest_certificate();
    int local_ok = handled && cert.valid && !cert.debug_only &&
        cert.evidence_kind == pvia::AuditEvidenceKind::PUBLIC_TRANSFER &&
        cert.checkpoint == checkpoint &&
        cert.label.obligation == pvia::Obligation::SEND &&
        backend().Judge(cert, runtime.session_id()) ? 1 : 0;

    const auto& auth = pvia::Ed25519TransferAuthenticator::instance();
    const pvia::Digest registry_anchor = auth.RegistryCommitment();
    const std::vector<u64> encoded =
        pvia::encode_public_transfer_blame_certificate(cert);
    bool standalone_ok = local_ok && !encoded.empty() &&
        pvia::Ed25519PublicTransferJudge::VerifyEncoded(
            encoded, runtime.session_id(), registry_anchor);
    pvia::Digest wrong_anchor = registry_anchor;
    wrong_anchor.bytes[0] ^= 1U;
    standalone_ok = standalone_ok &&
        !pvia::Ed25519PublicTransferJudge::VerifyEncoded(
            encoded, runtime.session_id(), wrong_anchor);
    std::vector<u64> tampered_encoded = encoded;
    if (!tampered_encoded.empty()) tampered_encoded.back() ^= 1ULL;
    standalone_ok = standalone_ok &&
        !pvia::Ed25519PublicTransferJudge::VerifyEncoded(
            tampered_encoded, runtime.session_id(), registry_anchor);
    local_ok = standalone_ok ? 1 : 0;
    int global_ok = 0;
    MPI_Allreduce(&local_ok, &global_ok, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    if (rank == 0) {
        std::cout << "[PVIA][secure-transfer-selftest] checkpoint="
                  << checkpoint << " certificate="
                  << (global_ok ? "ACCEPT" : "REJECT");
        if (cert.valid)
            std::cout << " accused=P" << cert.accused;
        std::cout << " standalone="
                  << (standalone_ok ? "ACCEPT" : "REJECT")
                  << "\n";
    }
    return global_ok != 0;
}
