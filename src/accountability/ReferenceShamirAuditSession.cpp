#include "ReferenceShamirAuditSession.hpp"
#include "MultiplicationConsistencySharingWitness.hpp"
#include "MultiplicationConsistencyProviderAbi.hpp"
#include "MultiplicationConsistencyProviderRelationReference.h"
#include "RobustAuditSession.hpp"
#include "AuthenticatedMpcAbortEvidence.hpp"
#include "../utils.hpp"

#include <mpi.h>

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <utility>
#include <vector>

namespace pvia {
namespace {

constexpr u64 SESSION_BIND_DOMAIN = 0x5056415544534553ULL; // PVAUDSES
constexpr u64 COEFFICIENT_DOMAIN = 0x5056415544434f45ULL;  // PVAUDCOE
constexpr u64 CHALLENGE_DOMAIN = 0x505641554443484cULL;    // PVAUDCHL
constexpr u64 BATCH_ZERO_MULTIPLICATION_ID =
    0x50564241545a4552ULL; // PVBATZER
constexpr u64 SUBSET_COEFFICIENT_DOMAIN = 0x5056415544534346ULL; // PVAUDSCF
constexpr u64 SUBSET_CHALLENGE_DOMAIN = 0x5056415544534348ULL;   // PVAUDSCH
constexpr u64 AUDIT_AUTH_KIND_SUBSET_DOMAIN = 0x535542444f4d3031ULL; // SUBDOM01
constexpr u64 AUDIT_AUTH_KIND_SUBSET_COIN = 0x535542434f494e31ULL;   // SUBCOIN1
constexpr u64 AUDIT_AUTH_KIND_SUBSET_OPEN = 0x5355424f50454e31ULL;   // SUBOPEN1
constexpr u64 AUDIT_AUTH_PROTOCOL_DOMAIN = 0x5056415544415554ULL; // PVAUDAUT
constexpr u64 AUDIT_AUTH_TRANSCRIPT_DOMAIN = 0x505641555454524eULL; // PVAUTTRN
constexpr u64 AUDIT_AUTH_KIND_BACKEND_MODE = 0x5247424d4f444531ULL; // RGBMODE1
constexpr u64 AUDIT_AUTH_KIND_REG_READY = 0x5247524541445931ULL; // RGREADY1
constexpr u64 AUDIT_AUTH_KIND_REG_CAP = 0x5247434150303031ULL; // RGCAP001
constexpr u64 AUDIT_AUTH_KIND_OWNER_READY = 0x4f574e5244593031ULL; // OWNRDY01
constexpr u64 AUDIT_AUTH_KIND_PAYLOAD_SHAPE = 0x5041595348503031ULL; // PAYSHP01
constexpr u64 AUDIT_AUTH_KIND_VSS = 0x5245475653533031ULL; // REGVSS01
constexpr u64 AUDIT_AUTH_KIND_REG_PROOF = 0x5245475052463031ULL; // REGPRF01
constexpr u64 AUDIT_AUTH_KIND_REG_VERIFY = 0x5245475652463031ULL; // REGVRF01
constexpr u64 AUDIT_AUTH_KIND_SEAL_BINDING = 0x5345414c424e4431ULL; // SEALBND1
constexpr u64 AUDIT_AUTH_KIND_REG_SET = 0x5245475345543031ULL; // REGSET01
constexpr u64 AUDIT_AUTH_KIND_BATCH_COIN = 0x4241544348434f49ULL; // BATCHCOI
constexpr u64 AUDIT_AUTH_KIND_BATCH_STRONG_MODE = 0x42415443484d4f44ULL; // BATCHMOD
constexpr u64 AUDIT_AUTH_KIND_BATCH_PROVENANCE = 0x4650524f56424e44ULL; // FPROVBND
constexpr u64 AUDIT_AUTH_KIND_BATCH_MUL_BINDING = 0x424d554c424e4431ULL; // BMULBND1
constexpr u64 AUDIT_AUTH_KIND_BATCH_OPEN_BINDING = 0x424f504e424e4431ULL; // BOPNBND1

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

F digest_to_field(const Digest& digest) {
    u64 real = 0, img = 0;
    std::memcpy(&real, digest.bytes.data(), 8);
    std::memcpy(&img, digest.bytes.data() + 8, 8);
    return F(static_cast<long long>(real % F::mod),
             static_cast<long long>(img % F::mod));
}

Digest digest_from_words(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    if (offset > words.size() || words.size() - offset < 4) return digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}

bool all_ranks_same_digest(const Digest& digest, int world_size) {
    std::vector<uint8_t> gathered(
        static_cast<size_t>(world_size) * digest.bytes.size());
    MPI_Allgather(digest.bytes.data(), static_cast<int>(digest.bytes.size()),
                  MPI_BYTE, gathered.data(), static_cast<int>(digest.bytes.size()),
                  MPI_BYTE, MPI_COMM_WORLD);
    for (int i = 0; i < world_size; ++i) {
        const uint8_t* begin = gathered.data() +
            static_cast<size_t>(i) * digest.bytes.size();
        if (!std::equal(digest.bytes.begin(), digest.bytes.end(), begin))
            return false;
    }
    return true;
}


std::vector<u64> encode_registration_proof(
    const RegistrationConsistencyProofArtifact& proof) {
    std::vector<u64> words = {
        proof.available ? 1ULL : 0ULL,
        proof.cryptographically_authenticated ? 1ULL : 0ULL,
        proof.zero_knowledge ? 1ULL : 0ULL,
        proof.proof_system_id,
        static_cast<u64>(proof.proof_words.size())};
    append_digest(proof.statement_binding, &words);
    append_digest(proof.transcript_binding, &words);
    append_digest(proof.proof_commitment, &words);
    words.insert(words.end(), proof.proof_words.begin(), proof.proof_words.end());
    return words;
}

bool decode_registration_proof(
    const std::vector<u64>& words,
    RegistrationConsistencyProofArtifact* proof) {
    if (!proof || words.size() < 17 || words[0] > 1 || words[1] > 1 ||
        words[2] > 1 || words[3] > std::numeric_limits<uint32_t>::max() ||
        words[4] >
            static_cast<u64>(std::numeric_limits<size_t>::max()))
        return false;
    const size_t proof_count = static_cast<size_t>(words[4]);
    if (proof_count != words.size() - 17) return false;
    *proof = RegistrationConsistencyProofArtifact{};
    proof->available = words[0] != 0;
    proof->cryptographically_authenticated = words[1] != 0;
    proof->zero_knowledge = words[2] != 0;
    proof->proof_system_id = static_cast<uint32_t>(words[3]);
    proof->statement_binding = digest_from_words(words, 5);
    proof->transcript_binding = digest_from_words(words, 9);
    proof->proof_commitment = digest_from_words(words, 13);
    proof->proof_words.assign(words.begin() + 17, words.end());
    return true;
}


} // namespace
ReferenceShamirAuditSession::ReferenceShamirAuditSession(
    uint64_t session_id, CheckpointId checkpoint,
    int rank, int world_size, int threshold,
    const RegistrationConsistencyProofBackend*
        registration_consistency_backend,
    const MultiplicationConsistencyProofBackend*
        multiplication_consistency_backend,
    const AuthenticatedMpcExchange* authenticated_exchange)
    : session_id_(session_id), checkpoint_(checkpoint),
      rank_(rank), world_size_(world_size),
      mpc_(rank, world_size, threshold),
      vss_(rank, world_size, threshold),
      registration_consistency_backend_(registration_consistency_backend) {
    if (authenticated_exchange &&
        mpc_.SetAuthenticatedTransport(
            authenticated_exchange, session_id_, checkpoint_))
        authenticated_exchange_ = authenticated_exchange;
    if (multiplication_consistency_backend &&
        mpc_.SetMultiplicationConsistencyProofBackend(
            multiplication_consistency_backend) &&
        mpc_.multiplication_consistency_available())
        multiplication_consistency_backend_ =
            multiplication_consistency_backend;
}

AuthenticatedMpcMessageContext
ReferenceShamirAuditSession::NextTransportContext(
    u64 message_kind, uint64_t round) const {
    AuthenticatedMpcMessageContext context;
    if (!authenticated_transport_enabled() || message_kind == 0)
        return context;
    context.protocol_domain = AUDIT_AUTH_PROTOCOL_DOMAIN;
    context.sid = session_id_;
    context.checkpoint = checkpoint_;
    context.round = round;
    context.sequence = transport_sequence_++;
    context.message_kind = message_kind;
    return context;
}

void ReferenceShamirAuditSession::BindTransportTranscript(
    const Digest& binding) const {
    if (!authenticated_transport_enabled() || binding == Digest{}) return;
    std::vector<u64> words = {
        AUDIT_AUTH_TRANSCRIPT_DOMAIN, session_id_, checkpoint_};
    append_digest(authenticated_transport_capability_binding(), &words);
    append_digest(authenticated_transport_transcript_binding_, &words);
    append_digest(binding, &words);
    authenticated_transport_transcript_binding_ = hash_words(words);
}

bool ReferenceShamirAuditSession::CollectiveSameWord(
    u64 local_value, u64 message_kind, uint64_t round,
    u64* agreed_value) const {
    if (!agreed_value || message_kind == 0) return false;
    if (authenticated_transport_enabled()) {
        std::vector<u64> gathered;
        Digest binding{};
        if (!authenticated_exchange_->AllGatherWords(
                NextTransportContext(message_kind, round),
                {local_value}, &gathered, &binding) ||
            gathered.size() != static_cast<size_t>(world_size_))
            return false;
        for (u64 value : gathered)
            if (value != gathered.front()) return false;
        *agreed_value = gathered.front();
        BindTransportTranscript(binding);
        return authenticated_transport_transcript_binding_ != Digest{};
    }
    std::vector<u64> gathered(static_cast<size_t>(world_size_));
    MPI_Allgather(&local_value, 1, MPI_UINT64_T,
                  gathered.data(), 1, MPI_UINT64_T, MPI_COMM_WORLD);
    for (u64 value : gathered)
        if (value != gathered.front()) return false;
    *agreed_value = gathered.front();
    return true;
}

bool ReferenceShamirAuditSession::CollectiveAllTrue(
    bool local_value, u64 message_kind, uint64_t round) const {
    if (message_kind == 0) return false;
    if (authenticated_transport_enabled()) {
        bool all_true = false;
        Digest binding{};
        if (!authenticated_exchange_->AllTrue(
                NextTransportContext(message_kind, round),
                local_value, &all_true, &binding))
            return false;
        BindTransportTranscript(binding);
        return all_true && authenticated_transport_transcript_binding_ != Digest{};
    }
    int local = local_value ? 1 : 0;
    int global = 0;
    MPI_Allreduce(&local, &global, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    return global != 0;
}

bool ReferenceShamirAuditSession::CollectiveSameDigest(
    const Digest& local_digest, u64 message_kind, uint64_t round) const {
    if (local_digest == Digest{} || message_kind == 0) return false;
    if (authenticated_transport_enabled()) {
        std::vector<u64> local_words;
        append_digest(local_digest, &local_words);
        std::vector<u64> gathered;
        Digest binding{};
        if (!authenticated_exchange_->AllGatherWords(
                NextTransportContext(message_kind, round),
                local_words, &gathered, &binding) ||
            gathered.size() != static_cast<size_t>(world_size_) * 4)
            return false;
        const Digest first = digest_from_words(gathered, 0);
        if (first == Digest{}) return false;
        for (int participant = 1; participant < world_size_; ++participant)
            if (digest_from_words(
                    gathered, static_cast<size_t>(participant) * 4) != first)
                return false;
        BindTransportTranscript(binding);
        return authenticated_transport_transcript_binding_ != Digest{};
    }
    return all_ranks_same_digest(local_digest, world_size_);
}

bool ReferenceShamirAuditSession::BroadcastWords(
    int owner, const std::vector<u64>& owner_payload,
    u64 message_kind, uint64_t round, std::vector<u64>* payload) const {
    if (!payload || owner < 0 || owner >= world_size_ || message_kind == 0)
        return false;
    if (authenticated_transport_enabled()) {
        Digest binding{};
        if (!authenticated_exchange_->BroadcastWords(
                NextTransportContext(message_kind, round), owner,
                owner_payload, payload, &binding))
            return false;
        BindTransportTranscript(binding);
        return authenticated_transport_transcript_binding_ != Digest{};
    }
    u64 word_count = rank_ == owner
        ? static_cast<u64>(owner_payload.size()) : 0ULL;
    MPI_Bcast(&word_count, 1, MPI_UINT64_T, owner, MPI_COMM_WORLD);
    if (word_count > static_cast<u64>(std::numeric_limits<int>::max()) ||
        word_count > static_cast<u64>(std::numeric_limits<size_t>::max()))
        return false;
    if (rank_ == owner) {
        *payload = owner_payload;
    } else {
        payload->assign(static_cast<size_t>(word_count), 0);
    }
    if (word_count > 0)
        MPI_Bcast(payload->data(), static_cast<int>(word_count),
                  MPI_UINT64_T, owner, MPI_COMM_WORLD);
    return true;
}

bool ReferenceShamirAuditSession::RegisterFoldOperation(
    uint32_t owner, const OperationRef& ref, const F& public_challenge,
    const Digest& public_state_digest,
    const Digest& public_actual_digest,
    const Digest& operation_statement_binding,
    const std::vector<F>& owner_private_state,
    const std::vector<F>& owner_actual_output) {
    if (sealed_ || !mpc_.valid() || session_id_ == 0 || checkpoint_ == 0 ||
        owner >= static_cast<uint32_t>(world_size_) || ref.owner != owner)
        return false;
    if (std::any_of(operations_.begin(), operations_.end(),
            [&](const FoldOperationShares& item) { return item.ref == ref; }))
        return false;
    if (public_state_digest == Digest{} || public_actual_digest == Digest{} ||
        operation_statement_binding == Digest{})
        return false;
    const u64 local_backend_mode =
        registration_consistency_backend_ ? 1ULL : 0ULL;
    u64 backend_mode = 0;
    if (!CollectiveSameWord(local_backend_mode,
            AUDIT_AUTH_KIND_BACKEND_MODE, ref.object_id, &backend_mode))
        return false;
    const bool require_registration_consistency = backend_mode != 0;
    RegistrationConsistencyCapabilities registration_capabilities;
    if (require_registration_consistency) {
        registration_capabilities =
            registration_consistency_backend_->Capabilities();
        const bool local_ready =
            production_ready_registration_consistency_capabilities(
                registration_capabilities);
        if (!CollectiveAllTrue(local_ready, AUDIT_AUTH_KIND_REG_READY,
                ref.object_id) ||
            !CollectiveSameDigest(
                registration_capabilities.capability_binding,
                AUDIT_AUTH_KIND_REG_CAP, ref.object_id) ||
            !vss_.valid())
            return false;
    }
    int local_consistency = 1;
    if (rank_ == static_cast<int>(owner)) {
        local_consistency = !owner_private_state.empty() &&
            !owner_actual_output.empty() &&
            hash_field_vector(owner_private_state) == public_state_digest &&
            hash_field_vector(owner_actual_output) == public_actual_digest ? 1 : 0;
    }
    if (!CollectiveAllTrue(local_consistency != 0,
            AUDIT_AUTH_KIND_OWNER_READY, ref.object_id))
        return false;

    std::vector<u64> owner_sizes;
    if (rank_ == static_cast<int>(owner))
        owner_sizes = {static_cast<u64>(owner_private_state.size()),
                       static_cast<u64>(owner_actual_output.size())};
    std::vector<u64> received_sizes;
    if (!BroadcastWords(static_cast<int>(owner), owner_sizes,
            AUDIT_AUTH_KIND_PAYLOAD_SHAPE, ref.object_id, &received_sizes) ||
        received_sizes.size() != 2)
        return false;
    const u64 payload_sizes[2] = {received_sizes[0], received_sizes[1]};
    if (payload_sizes[0] == 0 || payload_sizes[1] == 0 ||
        payload_sizes[0] > static_cast<u64>(std::numeric_limits<size_t>::max()) ||
        payload_sizes[1] > static_cast<u64>(std::numeric_limits<size_t>::max()) ||
        payload_sizes[0] > std::numeric_limits<u64>::max() - payload_sizes[1])
        return false;
    std::vector<F> combined_plaintext;
    if (rank_ == static_cast<int>(owner)) {
        combined_plaintext.reserve(owner_private_state.size() +
                                   owner_actual_output.size());
        combined_plaintext.insert(combined_plaintext.end(),
                                  owner_private_state.begin(),
                                  owner_private_state.end());
        combined_plaintext.insert(combined_plaintext.end(),
                                  owner_actual_output.begin(),
                                  owner_actual_output.end());
    }
    std::vector<F> combined_shares;
    Digest vss_transcript_binding{};
    ReferenceVssLocalWitness vss_local_witness;
    if (vss_.valid()) {
        ReferenceVssReceipt receipt;
        const bool shared = authenticated_transport_enabled()
            ? vss_.ShareVectorFromDealerAuthenticated(
                static_cast<int>(owner), combined_plaintext,
                &combined_shares, &receipt, *authenticated_exchange_,
                NextTransportContext(AUDIT_AUTH_KIND_VSS, ref.object_id),
                nullptr, &vss_local_witness)
            : vss_.ShareVectorFromDealerWithLocalWitness(
                static_cast<int>(owner), combined_plaintext,
                &combined_shares, &receipt, &vss_local_witness);
        if (!shared || !receipt.available || !receipt.consistent ||
            receipt.transcript_binding == Digest{} ||
            !validate_reference_vss_local_witness(vss_local_witness) ||
            vss_local_witness.transcript_binding != receipt.transcript_binding)
            return false;
        vss_transcript_binding = receipt.transcript_binding;
        if (authenticated_transport_enabled())
            BindTransportTranscript(receipt.transcript_binding);
    } else {
        if (authenticated_transport_enabled() ||
            !mpc_.ShareVectorFromDealer(
                static_cast<int>(owner), combined_plaintext, &combined_shares))
            return false;
    }
    const size_t state_count = static_cast<size_t>(payload_sizes[0]);
    const size_t actual_count = static_cast<size_t>(payload_sizes[1]);
    if (combined_shares.size() != state_count + actual_count) return false;
    std::vector<F> state_shares(
        combined_shares.begin(), combined_shares.begin() + state_count);
    std::vector<F> actual_shares(
        combined_shares.begin() + state_count, combined_shares.end());

    RegistrationConsistencyProofArtifact registration_proof;
    if (require_registration_consistency) {
        RegistrationConsistencyStatement statement;
        statement.sid = session_id_;
        statement.checkpoint = checkpoint_;
        statement.ref = ref;
        statement.kernel = AuditRelationKernel::FOLD_RS;
        statement.state_element_count = state_count;
        statement.output_element_count = actual_count;
        statement.public_state_digest = public_state_digest;
        statement.public_actual_digest = public_actual_digest;
        statement.operation_statement_binding = operation_statement_binding;
        statement.sharing_transcript_binding = vss_transcript_binding;
        statement.statement_binding =
            compute_registration_consistency_statement_binding(statement);
        if (!validate_registration_consistency_statement(statement)) return false;
        std::vector<u64> owner_proof_words;
        if (rank_ == static_cast<int>(owner)) {
            RegistrationConsistencyWitness witness;
            witness.state_values = owner_private_state;
            witness.actual_output = owner_actual_output;
            registration_proof = registration_consistency_backend_->Prove(
                statement, witness);
            owner_proof_words = encode_registration_proof(registration_proof);
        }
        std::vector<u64> proof_words;
        if (!BroadcastWords(static_cast<int>(owner), owner_proof_words,
                AUDIT_AUTH_KIND_REG_PROOF, ref.object_id, &proof_words) ||
            !decode_registration_proof(proof_words, &registration_proof))
            return false;
        const bool local_verified =
            validate_registration_consistency_proof_artifact(
                statement, registration_proof) &&
            registration_consistency_backend_->Verify(
                statement, registration_proof);
        if (!CollectiveAllTrue(local_verified, AUDIT_AUTH_KIND_REG_VERIFY,
                ref.object_id))
            return false;
    }

    std::vector<F> expected_shares;
    if (!recompute_fold_rs_output(
            state_shares, public_challenge, &expected_shares) ||
        expected_shares.size() != actual_shares.size())
        return false;
    FoldOperationShares operation;
    operation.owner = owner;
    operation.ref = ref;
    operation.public_challenge = public_challenge;
    operation.public_state_digest = public_state_digest;
    operation.public_actual_digest = public_actual_digest;
    operation.operation_statement_binding = operation_statement_binding;
    operation.vss_transcript_binding = vss_transcript_binding;
    operation.vss_local_witness = std::move(vss_local_witness);
    operation.registration_consistency_proof =
        std::move(registration_proof);
    operation.state_shares = std::move(state_shares);
    operation.actual_output_shares = std::move(actual_shares);
    operation.residual_shares.resize(operation.actual_output_shares.size(), F(0));
    for (size_t i = 0; i < operation.actual_output_shares.size(); ++i)
        operation.residual_shares[i] =
            operation.actual_output_shares[i] - expected_shares[i];
    operations_.push_back(std::move(operation));
    return true;
}

Digest ReferenceShamirAuditSession::ComputeRegistrationBinding() const {
    std::vector<u64> words = {
        SESSION_BIND_DOMAIN,
        session_id_,
        checkpoint_,
        static_cast<u64>(world_size_),
        static_cast<u64>(mpc_.threshold()),
        authenticated_transport_enabled() ? 1ULL : 0ULL,
        static_cast<u64>(operations_.size())};
    if (authenticated_transport_enabled()) {
        const Digest capability_binding =
            authenticated_transport_capability_binding();
        if (capability_binding == Digest{} ||
            authenticated_transport_transcript_binding_ == Digest{})
            return Digest{};
        append_digest(capability_binding, &words);
        append_digest(authenticated_transport_transcript_binding_, &words);
    }
    for (const auto& operation : operations_) {
        words.push_back(operation.owner);
        words.push_back(operation.ref.object_id);
        words.push_back(static_cast<u64>(operation.residual_shares.size()));
        append_digest(hash_field_vector({operation.public_challenge}), &words);
        append_digest(operation.public_state_digest, &words);
        append_digest(operation.public_actual_digest, &words);
        append_digest(operation.operation_statement_binding, &words);
        append_digest(operation.vss_transcript_binding, &words);
        append_digest(
            operation.registration_consistency_proof.proof_commitment,
            &words);
    }
    return hash_words(words);
}

bool ReferenceShamirAuditSession::SealRegistration() {
    if (sealed_ || !mpc_.valid() || operations_.empty()) return false;
    const Digest local_binding = ComputeRegistrationBinding();
    if (local_binding == Digest{} ||
        !CollectiveSameDigest(local_binding, AUDIT_AUTH_KIND_SEAL_BINDING, 0))
        return false;
    Digest registration_consistency_binding{};
    if (registration_consistency_backend_) {
        std::vector<RegistrationConsistencyProofArtifact> proofs;
        proofs.reserve(operations_.size());
        for (const auto& operation : operations_) {
            if (!operation.registration_consistency_proof.available ||
                operation.registration_consistency_proof.proof_commitment == Digest{})
                return false;
            proofs.push_back(operation.registration_consistency_proof);
        }
        registration_consistency_binding =
            compute_registration_consistency_set_binding(proofs);
        if (registration_consistency_binding == Digest{} ||
            !CollectiveSameDigest(registration_consistency_binding,
                AUDIT_AUTH_KIND_REG_SET, 0))
            return false;
    }
    registration_binding_ = local_binding;
    registration_consistency_binding_ = registration_consistency_binding;
    sealed_ = true;
    return true;
}

F ReferenceShamirAuditSession::DeriveCoefficient(
    const Digest& joint_seed, const OperationRef& ref,
    size_t coordinate) const {
    std::vector<u64> words = {
        COEFFICIENT_DOMAIN,
        session_id_, checkpoint_, ref.owner, ref.object_id,
        static_cast<u64>(coordinate)};
    append_digest(registration_binding_, &words);
    append_digest(joint_seed, &words);
    return digest_to_field(hash_words(words));
}

bool ReferenceShamirAuditSession::BuildFingerprintProvenance(
    const Digest& joint_seed, const F& fingerprint_share,
    ReferenceLinearSharingProvenance* provenance) const {
    if (!provenance || joint_seed == Digest{} || operations_.empty() ||
        !vss_.valid())
        return false;
    std::vector<ReferenceLinearSharingSource> sources;
    sources.reserve(operations_.size());
    for (const auto& operation : operations_) {
        const size_t state_count = operation.state_shares.size();
        const size_t output_count = operation.actual_output_shares.size();
        if (state_count < 2 || state_count % 2 != 0 ||
            output_count != state_count / 2 ||
            operation.vss_transcript_binding == Digest{} ||
            !validate_reference_vss_local_witness(
                operation.vss_local_witness) ||
            operation.vss_local_witness.transcript_binding !=
                operation.vss_transcript_binding ||
            operation.vss_local_witness.element_count !=
                state_count + output_count)
            return false;

        unsigned log_n = 0;
        size_t power = 1;
        while (power < state_count) {
            power <<= 1;
            ++log_n;
        }
        if (power != state_count) return false;
        const F two_inv = F(2).inv();
        F omega = getRootOfUnity(static_cast<int>(log_n));
        omega = omega.inv();
        F inv_omega(1);
        std::vector<F> coefficients(
            state_count + output_count, F(0));
        for (size_t i = 0; i < output_count; ++i) {
            const F audit_coefficient =
                DeriveCoefficient(joint_seed, operation.ref, i);
            const F left_fold = two_inv * (
                (F(1) - operation.public_challenge) +
                operation.public_challenge * inv_omega);
            const F right_fold = two_inv * (
                (F(1) - operation.public_challenge) -
                operation.public_challenge * inv_omega);
            coefficients[i] += F(0) - audit_coefficient * left_fold;
            coefficients[i + output_count] +=
                F(0) - audit_coefficient * right_fold;
            coefficients[state_count + i] += audit_coefficient;
            inv_omega *= omega;
        }
        ReferenceLinearSharingSource source;
        source.sharing_binding = operation.vss_transcript_binding;
        source.element_coefficients = std::move(coefficients);
        source.local_witness = operation.vss_local_witness;
        sources.push_back(std::move(source));
    }
    if (!build_reference_linear_sharing_provenance(
            std::move(sources), provenance))
        return false;
    return provenance->local_share == fingerprint_share &&
        provenance->binding != Digest{};
}

ReferenceShamirBatchResult ReferenceShamirAuditSession::BatchCheck() const {
    ReferenceShamirBatchResult result;
    result.checkpoint = checkpoint_;
    result.operation_count = operations_.size();
    result.registration_binding = registration_binding_;
    if (!sealed_ || registration_binding_ == Digest{} || operations_.empty())
        return result;
    Digest joint_seed{};
    Digest public_coin_transcript_binding{};
    if (!mpc_.JointPublicSeed(
            &joint_seed, &public_coin_transcript_binding) ||
        public_coin_transcript_binding == Digest{})
        return result;
    result.public_coin_transcript_binding =
        public_coin_transcript_binding;
    if (!CollectiveSameDigest(
            public_coin_transcript_binding, AUDIT_AUTH_KIND_BATCH_COIN,
            BATCH_ZERO_MULTIPLICATION_ID))
        return result;
    std::vector<u64> challenge_words = {
        CHALLENGE_DOMAIN, session_id_, checkpoint_};
    append_digest(registration_binding_, &challenge_words);
    append_digest(public_coin_transcript_binding, &challenge_words);
    append_digest(joint_seed, &challenge_words);
    result.challenge_binding = hash_words(challenge_words);

    F fingerprint_share(0);
    for (const auto& operation : operations_) {
        for (size_t coordinate = 0;
             coordinate < operation.residual_shares.size(); ++coordinate) {
            const F coefficient = DeriveCoefficient(
                joint_seed, operation.ref, coordinate);
            fingerprint_share +=
                coefficient * operation.residual_shares[coordinate];
        }
    }

    const u64 local_strong_mode =
        multiplication_consistency_backend_ ? 1ULL : 0ULL;
    u64 agreed_strong_mode = 0;
    if (!CollectiveSameWord(
            local_strong_mode, AUDIT_AUTH_KIND_BATCH_STRONG_MODE,
            BATCH_ZERO_MULTIPLICATION_ID, &agreed_strong_mode) ||
        agreed_strong_mode > 1)
        return result;

    bool is_zero = false;
    Digest opening_transcript_binding{};
    if (agreed_strong_mode != 0) {
        ReferenceLinearSharingProvenance fingerprint_provenance;
        if (!BuildFingerprintProvenance(
                joint_seed, fingerprint_share, &fingerprint_provenance) ||
            !CollectiveSameDigest(
                fingerprint_provenance.binding,
                AUDIT_AUTH_KIND_BATCH_PROVENANCE,
                BATCH_ZERO_MULTIPLICATION_ID))
            return result;
        ReferenceMaskedZeroConsistencyContext zero_context;
        zero_context.sid = session_id_;
        zero_context.checkpoint = checkpoint_;
        zero_context.multiplication_id = BATCH_ZERO_MULTIPLICATION_ID;
        zero_context.context_binding = result.challenge_binding;
        Digest multiplication_consistency_binding{};
        if (!mpc_.MaskedZeroTestWithConsistency(
                fingerprint_provenance, zero_context,
                &is_zero, &opening_transcript_binding,
                &multiplication_consistency_binding) ||
            opening_transcript_binding == Digest{} ||
            multiplication_consistency_binding == Digest{})
            return result;
        result.multiplication_consistency_binding =
            multiplication_consistency_binding;
        if (!CollectiveSameDigest(
                multiplication_consistency_binding,
                AUDIT_AUTH_KIND_BATCH_MUL_BINDING,
                BATCH_ZERO_MULTIPLICATION_ID))
            return result;
    } else {
        if (!mpc_.MaskedZeroTest(
                fingerprint_share, &is_zero, &opening_transcript_binding) ||
            opening_transcript_binding == Digest{})
            return result;
    }
    result.opening_transcript_binding = opening_transcript_binding;
    if (!CollectiveSameDigest(
            opening_transcript_binding, AUDIT_AUTH_KIND_BATCH_OPEN_BINDING,
            BATCH_ZERO_MULTIPLICATION_ID))
        return result;
    result.available = true;
    result.clean = is_zero;
    return result;
}

ReferenceShamirSubsetResult ReferenceShamirAuditSession::BatchCheckSubset(
    const std::vector<OperationRef>& requested_operations,
    const Digest& domain_binding, uint64_t round_tag) const {
    ReferenceShamirSubsetResult result;
    result.checkpoint = checkpoint_;
    result.registration_binding = registration_binding_;
    if (!sealed_ || registration_binding_ == Digest{} ||
        requested_operations.empty() || domain_binding == Digest{} ||
        round_tag == 0)
        return result;

    std::vector<OperationRef> refs = requested_operations;
    std::sort(refs.begin(), refs.end(),
        [](const OperationRef& lhs, const OperationRef& rhs) {
            if (lhs.owner != rhs.owner) return lhs.owner < rhs.owner;
            return lhs.object_id < rhs.object_id;
        });
    if (std::adjacent_find(refs.begin(), refs.end()) != refs.end())
        return result;

    std::vector<const FoldOperationShares*> selected;
    selected.reserve(refs.size());
    for (const OperationRef& ref : refs) {
        const FoldOperationShares* found = nullptr;
        for (const auto& operation : operations_) {
            if (operation.ref == ref) {
                found = &operation;
                break;
            }
        }
        if (!found || found->residual_shares.empty()) return result;
        selected.push_back(found);
    }
    result.operation_count = selected.size();

    std::vector<u64> subset_words = {
        SUBSET_CHALLENGE_DOMAIN, session_id_, checkpoint_, round_tag,
        static_cast<u64>(refs.size())};
    append_digest(registration_binding_, &subset_words);
    append_digest(domain_binding, &subset_words);
    for (const OperationRef& ref : refs) {
        subset_words.push_back(ref.owner);
        subset_words.push_back(ref.object_id);
    }
    result.subset_binding = hash_words(subset_words);
    if (result.subset_binding == Digest{} ||
        !CollectiveSameDigest(
            result.subset_binding, AUDIT_AUTH_KIND_SUBSET_DOMAIN, round_tag))
        return result;

    Digest joint_seed{};
    Digest public_coin_transcript_binding{};
    if (!mpc_.JointPublicSeed(&joint_seed, &public_coin_transcript_binding) ||
        joint_seed == Digest{} || public_coin_transcript_binding == Digest{} ||
        !CollectiveSameDigest(
            public_coin_transcript_binding,
            AUDIT_AUTH_KIND_SUBSET_COIN, round_tag))
        return result;
    result.public_coin_transcript_binding = public_coin_transcript_binding;

    std::vector<u64> challenge_words = {
        SUBSET_CHALLENGE_DOMAIN, session_id_, checkpoint_, round_tag};
    append_digest(registration_binding_, &challenge_words);
    append_digest(domain_binding, &challenge_words);
    append_digest(result.subset_binding, &challenge_words);
    append_digest(public_coin_transcript_binding, &challenge_words);
    append_digest(joint_seed, &challenge_words);
    result.challenge_binding = hash_words(challenge_words);
    if (result.challenge_binding == Digest{}) return result;

    F fingerprint_share(0);
    for (const FoldOperationShares* operation : selected) {
        for (size_t coordinate = 0;
             coordinate < operation->residual_shares.size(); ++coordinate) {
            std::vector<u64> coefficient_words = {
                SUBSET_COEFFICIENT_DOMAIN, session_id_, checkpoint_, round_tag,
                operation->ref.owner, operation->ref.object_id,
                static_cast<u64>(coordinate)};
            append_digest(registration_binding_, &coefficient_words);
            append_digest(domain_binding, &coefficient_words);
            append_digest(result.subset_binding, &coefficient_words);
            append_digest(joint_seed, &coefficient_words);
            const F coefficient = digest_to_field(hash_words(coefficient_words));
            fingerprint_share += coefficient *
                operation->residual_shares[coordinate];
        }
    }

    bool is_zero = false;
    Digest opening_transcript_binding{};
    if (!mpc_.MaskedZeroTest(
            fingerprint_share, &is_zero, &opening_transcript_binding) ||
        opening_transcript_binding == Digest{} ||
        !CollectiveSameDigest(
            opening_transcript_binding,
            AUDIT_AUTH_KIND_SUBSET_OPEN, round_tag))
        return result;
    result.opening_transcript_binding = opening_transcript_binding;
    result.available = true;
    result.clean = is_zero;
    return result;
}

bool ReferenceShamirAuditSession::SelectAuditWitness(
    const OperationRef& ref,
    ReferenceShamirSelectedAuditWitness* witness) const {
    if (!witness || !sealed_) return false;
    *witness = ReferenceShamirSelectedAuditWitness{};
    for (const auto& operation : operations_) {
        if (operation.ref != ref) continue;
        if (operation.state_shares.empty() ||
            operation.actual_output_shares.empty())
            return false;
        if (operation.vss_transcript_binding != Digest{} &&
            (!validate_reference_vss_local_witness(
                 operation.vss_local_witness) ||
             operation.vss_local_witness.transcript_binding !=
                 operation.vss_transcript_binding))
            return false;
        witness->available = true;
        witness->ref = ref;
        witness->state_shares = operation.state_shares;
        witness->actual_output_shares = operation.actual_output_shares;
        witness->registration_vss_witness = operation.vss_local_witness;
        return true;
    }
    return false;
}

namespace {
// Synthetic wiring backend used only by this translation unit's self-test.
// It deliberately does not model a real ZK proof system and is never exposed
// through a runtime constructor. Its sole purpose is to exercise the generic
// registration-consistency proof plumbing end to end.
class SelfTestRegistrationConsistencyBackend final
    : public RegistrationConsistencyProofBackend {
public:
    RegistrationConsistencyCapabilities Capabilities() const override {
        RegistrationConsistencyCapabilities capabilities;
        capabilities.available = true;
        capabilities.malicious_sound = true;
        capabilities.zero_knowledge = true;
        capabilities.binds_sharing_transcript = true;
        capabilities.protocol_id = 0x5245475445535450ULL; // REGTESTP
        capabilities.implementation_binding =
            hash_words({0x5245475445535449ULL}); // REGTESTI
        capabilities.capability_binding =
            compute_registration_consistency_capability_binding(capabilities);
        return capabilities;
    }

    RegistrationConsistencyProofArtifact Prove(
        const RegistrationConsistencyStatement& statement,
        const RegistrationConsistencyWitness& witness) const override {
        RegistrationConsistencyProofArtifact proof;
        if (!validate_registration_consistency_statement(statement) ||
            hash_field_vector(witness.state_values) !=
                statement.public_state_digest ||
            hash_field_vector(witness.actual_output) !=
                statement.public_actual_digest)
            return proof;
        proof.available = true;
        proof.cryptographically_authenticated = true;
        proof.zero_knowledge = true;
        proof.proof_system_id = 0x52454754U; // REGT
        proof.statement_binding = statement.statement_binding;
        proof.transcript_binding = Transcript(statement);
        proof.proof_words = {
            0x5245475445535457ULL,
            static_cast<u64>(statement.state_element_count),
            static_cast<u64>(statement.output_element_count)};
        proof.proof_commitment =
            compute_registration_consistency_proof_commitment(proof);
        return proof;
    }


    bool Verify(
        const RegistrationConsistencyStatement& statement,
        const RegistrationConsistencyProofArtifact& proof) const override {
        if (!validate_registration_consistency_proof_artifact(statement, proof))
            return false;
        const std::vector<u64> expected_words = {
            0x5245475445535457ULL,
            static_cast<u64>(statement.state_element_count),
            static_cast<u64>(statement.output_element_count)};
        return proof.proof_words == expected_words &&
               proof.transcript_binding == Transcript(statement);
    }

private:
    mutable size_t relation_reference_count_ = 0;
    mutable size_t vss_local_prove_count_ = 0;
    mutable size_t linear_prove_count_ = 0;

    static Digest Transcript(
        const RegistrationConsistencyStatement& statement) {
        std::vector<u64> words = {
            0x5245475445535454ULL, statement.sid, statement.checkpoint,
            statement.ref.owner, statement.ref.object_id};
        append_digest(statement.statement_binding, &words);
        append_digest(statement.sharing_transcript_binding, &words);
        return hash_words(words);
    }
 };

// Synthetic multiplication-consistency backend for MPI wiring tests only.
// It checks the dealer-local witness before emitting a marker proof, but its
// public Verify routine is not a cryptographic ZK verifier. It is intentionally
// confined to this anonymous self-test namespace and never installed by the
// production/reference runtime adapter.
class SelfTestMultiplicationConsistencyBackend final
    : public MultiplicationConsistencyProofBackend {
public:
    size_t relation_reference_count() const {
        return relation_reference_count_;
    }
    size_t vss_local_prove_count() const {
        return vss_local_prove_count_;
    }
    size_t linear_prove_count() const {
        return linear_prove_count_;
    }

    MultiplicationConsistencyCapabilities Capabilities() const override {
        MultiplicationConsistencyCapabilities capabilities;
        capabilities.available = true;
        capabilities.malicious_sound = true;
        capabilities.zero_knowledge = true;
        capabilities.binds_input_sharings = true;
        capabilities.binds_output_sharing = true;
        capabilities.protocol_id = 0x4d554c5445535450ULL; // MULTESTP
        capabilities.relation_binding =
            compute_multiplication_consistency_relation_binding();
        capabilities.implementation_binding =
            hash_words({0x4d554c5445535449ULL}); // MULTESTI
        capabilities.capability_binding =
            compute_multiplication_consistency_capability_binding(capabilities);
        return capabilities;
    }

    MultiplicationConsistencyProofArtifact Prove(
        const MultiplicationConsistencyStatement& statement,
        const MultiplicationConsistencyWitness& witness) const override {
        MultiplicationConsistencyProofArtifact proof;
        if (!validate_multiplication_consistency_statement(statement) ||
            witness.product_value != witness.lhs_share * witness.rhs_share)
            return proof;

        const std::vector<uint64_t> statement_words =
            encode_multiplication_consistency_statement_abi(statement);
        const std::vector<uint64_t> witness_words =
            encode_multiplication_consistency_witness_abi(witness);
        if (statement_words.empty() || witness_words.empty() ||
            !pvia_mc_reference_validate_relation(
                statement_words.data(), statement_words.size(),
                witness_words.data(), witness_words.size()))
            return proof;

        MultiplicationConsistencySharingWitnessEnvelope lhs_envelope;
        MultiplicationConsistencySharingWitnessEnvelope rhs_envelope;
        if (!decode_multiplication_consistency_sharing_witness(
                witness.lhs_sharing_witness_words, &lhs_envelope) ||
            !decode_multiplication_consistency_sharing_witness(
                witness.rhs_sharing_witness_words, &rhs_envelope))
            return proof;

        const bool relation_vector_is_linear =
            lhs_envelope.kind ==
                MultiplicationConsistencySharingWitnessKind::
                    LINEAR_COMBINATION ||
            rhs_envelope.kind ==
                MultiplicationConsistencySharingWitnessKind::
                    LINEAR_COMBINATION;
        bool& relation_vector_written =
            relation_vector_is_linear
                ? exported_linear_vector_
                : exported_vss_vector_;
        const char* relation_vector_dir =
            std::getenv("PVIA_MC_PROVIDER_VECTOR_DIR");
        if (!relation_vector_written && relation_vector_dir &&
            relation_vector_dir[0] != 0) {
            int mpi_rank = 0;
            MPI_Comm_rank(MPI_COMM_WORLD, &mpi_rank);
            const std::string kind =
                relation_vector_is_linear ? "linear" : "vss_local";
            const std::string path =
                std::string(relation_vector_dir) +
                "/relation_" + kind + "_rank" +
                std::to_string(mpi_rank) + ".txt";
            std::ofstream out(path, std::ios::out | std::ios::trunc);
            if (out) {
                const auto relation_binding =
                    compute_multiplication_consistency_relation_binding();
                out << "PVIA_MC_PROVIDER_RELATION_VECTOR_V1\n";
                out << "abi_version="
                    << MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_VERSION
                    << "\n";
                out << "kind=" << kind << "\n";
                out << "rank=" << mpi_rank << "\n";
                out << "dealer=" << statement.dealer << "\n";
                out << "relation_binding="
                    << relation_binding.hex() << "\n";
                const std::vector<u64> statement_digest_words(
                    statement_words.begin(), statement_words.end());
                const std::vector<u64> witness_digest_words(
                    witness_words.begin(), witness_words.end());
                out << "statement_digest="
                    << hash_words(statement_digest_words).hex() << "\n";
                out << "witness_digest="
                    << hash_words(witness_digest_words).hex() << "\n";
                out << "statement_word_count="
                    << statement_words.size() << "\n";
                out << "statement_words=";
                for (size_t i = 0; i < statement_words.size(); ++i) {
                    if (i != 0) out << ",";
                    out << statement_words[i];
                }
                out << "\n";
                out << "witness_word_count="
                    << witness_words.size() << "\n";
                out << "witness_words=";
                for (size_t i = 0; i < witness_words.size(); ++i) {
                    if (i != 0) out << ",";
                    out << witness_words[i];
                }
                out << "\n";
                relation_vector_written = true;
            }
        }

        ++relation_reference_count_;
        if (lhs_envelope.kind ==
                MultiplicationConsistencySharingWitnessKind::VSS_LOCAL ||
            rhs_envelope.kind ==
                MultiplicationConsistencySharingWitnessKind::VSS_LOCAL)
            ++vss_local_prove_count_;
        if (lhs_envelope.kind ==
                MultiplicationConsistencySharingWitnessKind::LINEAR_COMBINATION ||
            rhs_envelope.kind ==
                MultiplicationConsistencySharingWitnessKind::LINEAR_COMBINATION)
            ++linear_prove_count_;

        auto validate_input = [&](
            const std::vector<u64>& words, const Digest& binding,
            const F& expected_share) -> bool {
            MultiplicationConsistencySharingWitnessEnvelope envelope;
            if (!decode_multiplication_consistency_sharing_witness(
                    words, &envelope) ||
                envelope.sharing_binding != binding)
                return false;
            if (envelope.kind ==
                MultiplicationConsistencySharingWitnessKind::
                    LINEAR_COMBINATION) {
                ReferenceLinearSharingProvenance linear;
                if (!decode_reference_linear_sharing_provenance(
                        envelope.payload_words, &linear) ||
                    linear.binding != binding ||
                    linear.local_share != expected_share)
                    return false;
                for (const auto& source : linear.sources) {
                    if (source.local_witness.participant !=
                            static_cast<int>(statement.dealer) ||
                        source.local_witness.transcript_binding !=
                            source.sharing_binding)
                        return false;
                }
                return true;
            }
            if (envelope.kind !=
                MultiplicationConsistencySharingWitnessKind::VSS_LOCAL)
                return false;
            ReferenceVssLocalWitness direct;
            if (!decode_reference_vss_local_witness(
                    envelope.payload_words, &direct) ||
                direct.participant != static_cast<int>(statement.dealer) ||
                direct.transcript_binding != binding ||
                direct.local_row_words.size() < 2)
                return false;
            const F direct_value(
                static_cast<long long>(direct.local_row_words[0]),
                static_cast<long long>(direct.local_row_words[1]));
            return direct_value == expected_share;
        };
        MultiplicationConsistencySharingWitnessEnvelope output_envelope;
        ReferenceVssDealerWitness output_witness;
        if (!validate_input(
                witness.lhs_sharing_witness_words,
                statement.lhs_sharing_binding, witness.lhs_share) ||
            !validate_input(
                witness.rhs_sharing_witness_words,
                statement.rhs_sharing_binding, witness.rhs_share) ||
            !decode_multiplication_consistency_sharing_witness(
                witness.output_sharing_witness_words, &output_envelope) ||
            output_envelope.kind !=
                MultiplicationConsistencySharingWitnessKind::VSS_DEALER ||
            output_envelope.sharing_binding !=
                statement.output_sharing_binding ||
            !decode_reference_vss_dealer_witness(
                output_envelope.payload_words, &output_witness) ||
            output_witness.dealer != static_cast<int>(statement.dealer) ||
            output_witness.transcript_binding !=
                statement.output_sharing_binding ||
            output_witness.coefficient_words.size() < 2)
            return proof;
        const F shared_constant(
            static_cast<long long>(output_witness.coefficient_words[0]),
            static_cast<long long>(output_witness.coefficient_words[1]));
        if (shared_constant != witness.product_value) return proof;
        proof.available = true;
        proof.cryptographically_authenticated = true;
        proof.zero_knowledge = true;
        proof.proof_system_id = 0x4d554c54U; // MULT
        proof.statement_binding = statement.statement_binding;
        proof.transcript_binding = Transcript(statement);
        proof.proof_words = {
            0x4d554c5445535457ULL,
            static_cast<u64>(statement.dealer)};
        proof.proof_commitment =
            compute_multiplication_consistency_proof_commitment(proof);
        return proof;
    }

    bool Verify(
        const MultiplicationConsistencyStatement& statement,
        const MultiplicationConsistencyProofArtifact& proof) const override {
        if (!validate_multiplication_consistency_proof_artifact(
                statement, proof))
            return false;
        return proof.proof_words == std::vector<u64>{
                   0x4d554c5445535457ULL,
                   static_cast<u64>(statement.dealer)} &&
               proof.transcript_binding == Transcript(statement);
    }

private:
    mutable size_t relation_reference_count_ = 0;
    mutable size_t vss_local_prove_count_ = 0;
    mutable size_t linear_prove_count_ = 0;
    mutable bool exported_vss_vector_ = false;
    mutable bool exported_linear_vector_ = false;
    static Digest Transcript(
        const MultiplicationConsistencyStatement& statement) {
        std::vector<u64> words = {
            0x4d554c5445535454ULL,
            statement.sid, statement.checkpoint,
            statement.multiplication_id, statement.dealer};
        append_digest(statement.statement_binding, &words);
        append_digest(statement.output_sharing_binding, &words);
        return hash_words(words);
    }
};

bool run_strong_batch_once(
    int rank, int world_size, bool inject_mismatch,
    ReferenceShamirBatchResult* batch_out) {
    if (!batch_out || world_size < 3) return false;
    const int threshold = (world_size - 1) / 3;
    SelfTestMultiplicationConsistencyBackend multiplication_backend;
    const uint64_t sid = 0x5354524f4e474241ULL; // STRONGBA
    const CheckpointId checkpoint = inject_mismatch
        ? 0x5354524f4e470002ULL : 0x5354524f4e470001ULL;
    ReferenceShamirAuditSession session(
        sid, checkpoint, rank, world_size, threshold,
        nullptr, &multiplication_backend);
    if (!session.multiplication_consistency_enabled()) return false;

    for (int owner = 0; owner < world_size; ++owner) {
        const F challenge(owner + 5, owner + 1);
        std::vector<F> state(8);
        for (size_t i = 0; i < state.size(); ++i)
            state[i] = F(
                700 * (owner + 1) + static_cast<int>(i) + 1,
                30 + static_cast<int>(i));
        std::vector<F> output;
        if (!recompute_fold_rs_output(state, challenge, &output))
            return false;
        if (inject_mismatch && owner == 0 && !output.empty())
            output[0] += F(1);
        std::vector<F> owner_state;
        std::vector<F> owner_output;
        if (rank == owner) {
            owner_state = state;
            owner_output = output;
        }
        const OperationRef ref{
            static_cast<uint32_t>(owner),
            static_cast<uint64_t>(0x53540000ULL + owner)};
        const Digest statement = hash_words({
            sid, checkpoint, static_cast<u64>(owner), ref.object_id,
            0x5354524f4e47464fULL});
        if (!session.RegisterFoldOperation(
                static_cast<uint32_t>(owner), ref, challenge,
                hash_field_vector(state), hash_field_vector(output),
                statement, owner_state, owner_output))
            return false;
    }
    if (!session.SealRegistration()) return false;
    *batch_out = session.BatchCheck();
    return batch_out->available &&
        batch_out->multiplication_consistency_binding != Digest{} &&
        batch_out->opening_transcript_binding != Digest{} &&
        multiplication_backend.relation_reference_count() > 0 &&
        multiplication_backend.linear_prove_count() > 0;
}

bool run_one_reference_session(
    int rank, int world_size, bool inject_mismatch,
    ReferenceShamirBatchResult* batch_out) {
    if (!batch_out || world_size < 3) return false;
    const int threshold = (world_size - 1) / 2;
    if (2 * threshold >= world_size) return false;
    const uint64_t sid = 0x5245464d50434155ULL; // REFMPCAU
    const CheckpointId checkpoint = inject_mismatch
        ? 0x5245464d50430002ULL : 0x5245464d50430001ULL;
    ReferenceShamirAuditSession session(
        sid, checkpoint, rank, world_size, threshold);

    for (int owner = 0; owner < world_size; ++owner) {
        const F challenge(owner + 3);
        std::vector<F> canonical_state(8);
        for (size_t i = 0; i < canonical_state.size(); ++i)
            canonical_state[i] =
                F(100 * (owner + 1) + static_cast<int>(i) + 1);
        std::vector<F> canonical_output;
        if (!recompute_fold_rs_output(
                canonical_state, challenge, &canonical_output))
            return false;
        if (inject_mismatch && owner == 0 && !canonical_output.empty())
            canonical_output[0] += F(1);

        std::vector<F> private_state;
        std::vector<F> actual_output;
        if (rank == owner) {
            private_state = canonical_state;
            actual_output = canonical_output;
        }
        const OperationRef ref{
            static_cast<uint32_t>(owner),
            static_cast<uint64_t>(1000 + owner)};
        const Digest statement = hash_words({
            sid, checkpoint, static_cast<u64>(owner), ref.object_id,
            0x464f4c445f524546ULL});
        if (!session.RegisterFoldOperation(
                static_cast<uint32_t>(owner), ref, challenge,
                hash_field_vector(canonical_state),
                hash_field_vector(canonical_output), statement,
                private_state, actual_output))
            return false;
    }

    if (!session.SealRegistration()) return false;
    for (int owner = 0; owner < world_size; ++owner) {
        ReferenceShamirSelectedAuditWitness witness;
        const OperationRef ref{static_cast<uint32_t>(owner),
                               static_cast<uint64_t>(1000 + owner)};
        if (!session.SelectAuditWitness(ref, &witness) || !witness.available ||
            witness.state_shares.size() != 8 ||
            witness.actual_output_shares.size() != 4)
            return false;
    }
    *batch_out = session.BatchCheck();
    return batch_out->available &&
           batch_out->operation_count == static_cast<size_t>(world_size);
}
bool run_registration_consistency_wiring_selftest(
    int rank, int world_size, bool* consistency_bound) {
    if (!consistency_bound || world_size < 3) return false;
    const int threshold = (world_size - 1) / 3;
    SelfTestRegistrationConsistencyBackend backend;
    const uint64_t sid = 0x524547434f4e5354ULL; // REGCONST
    const CheckpointId checkpoint = 0x524547434f4e0001ULL;
    ReferenceShamirAuditSession session(
        sid, checkpoint, rank, world_size, threshold, &backend);

    const F challenge(7, 3);
    std::vector<F> state(8);
    for (size_t i = 0; i < state.size(); ++i)
        state[i] = F(static_cast<long long>(300 + i),
                     static_cast<long long>(900 + 2 * i));
    std::vector<F> output;
    if (!recompute_fold_rs_output(state, challenge, &output)) return false;
    std::vector<F> owner_state;
    std::vector<F> owner_output;
    if (rank == 0) {
        owner_state = state;
        owner_output = output;
    }
    const OperationRef ref{0, 0x524547434f4e0002ULL};
    const Digest operation_statement = hash_words({
        sid, checkpoint, ref.owner, ref.object_id, 0x524547434f4e5354ULL});
    if (!session.RegisterFoldOperation(
            0, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), operation_statement,
            owner_state, owner_output) ||
        !session.SealRegistration())
        return false;
    const ReferenceShamirBatchResult batch = session.BatchCheck();
    *consistency_bound = batch.available && batch.clean &&
        session.registration_consistency_binding() != Digest{};
    return true;
}

bool run_multiplication_consistency_wiring_selftest(
    int rank, int world_size, bool* consistency_bound,
    bool* missing_backend_rejected) {
    if (!consistency_bound || !missing_backend_rejected || world_size < 3)
        return false;
    const int threshold = (world_size - 1) / 3;
    ReferenceBivariateVss vss(rank, world_size, threshold);
    ReferenceShamirMpc mpc(rank, world_size, threshold);
    if (!vss.valid() || !mpc.valid() ||
        !mpc.detectable_degree_reduction_available())
        return false;

    const F lhs_secret(13, 5);
    const F rhs_secret(17, 2);
    std::vector<F> lhs_plaintext;
    std::vector<F> rhs_plaintext;
    if (rank == 0) lhs_plaintext = {lhs_secret};
    const int rhs_dealer = world_size > 1 ? 1 : 0;
    if (rank == rhs_dealer) rhs_plaintext = {rhs_secret};
    std::vector<F> lhs_shares;
    std::vector<F> rhs_shares;
    ReferenceVssReceipt lhs_receipt;
    ReferenceVssReceipt rhs_receipt;
    ReferenceVssDealerWitness lhs_dealer_witness;
    ReferenceVssDealerWitness rhs_dealer_witness;
    ReferenceVssLocalWitness lhs_local_witness;
    ReferenceVssLocalWitness rhs_local_witness;
    if (!vss.ShareVectorFromDealerWithWitnesses(
            0, lhs_plaintext, &lhs_shares, &lhs_receipt,
            &lhs_dealer_witness, &lhs_local_witness) ||
        !vss.ShareVectorFromDealerWithWitnesses(
            rhs_dealer, rhs_plaintext, &rhs_shares, &rhs_receipt,
            &rhs_dealer_witness, &rhs_local_witness) ||
        lhs_shares.size() != 1 || rhs_shares.size() != 1 ||
        lhs_receipt.transcript_binding == Digest{} ||
        rhs_receipt.transcript_binding == Digest{} ||
        !validate_reference_vss_local_witness(lhs_local_witness) ||
        !validate_reference_vss_local_witness(rhs_local_witness))
        return false;

    ReferenceMultiplicationConsistencyContext context;
    context.sid = 0x4d554c434f4e5354ULL; // MULCONST
    context.checkpoint = 0x4d554c434f4e0001ULL;
    context.multiplication_id = 1;
    context.lhs_sharing_binding = lhs_receipt.transcript_binding;
    context.rhs_sharing_binding = rhs_receipt.transcript_binding;
    context.context_binding = hash_words({
        0x4d554c434f4e4354ULL, context.sid, context.checkpoint,
        context.multiplication_id});

    ReferenceMultiplicationConsistencyLocalWitness local_witness;
    local_witness.lhs_sharing_witness_words =
        encode_reference_vss_local_witness(lhs_local_witness);
    local_witness.rhs_sharing_witness_words =
        encode_reference_vss_local_witness(rhs_local_witness);
    if (local_witness.lhs_sharing_witness_words.empty() ||
        local_witness.rhs_sharing_witness_words.empty())
        return false;

    ReferenceShamirMpc fail_closed_mpc(rank, world_size, threshold);
    F rejected_product(0);
    Digest rejected_binding{};
    *missing_backend_rejected = !fail_closed_mpc.MultiplyWithConsistency(
        lhs_shares.front(), rhs_shares.front(), context, local_witness,
        &rejected_product, &rejected_binding);

    SelfTestMultiplicationConsistencyBackend backend;
    if (!mpc.SetMultiplicationConsistencyProofBackend(&backend) ||
        !mpc.multiplication_consistency_available())
        return false;
    F product_share(0);
    Digest multiplication_binding{};
    if (!mpc.MultiplyWithConsistency(
            lhs_shares.front(), rhs_shares.front(), context, local_witness,
            &product_share, &multiplication_binding) ||
        multiplication_binding == Digest{})
        return false;
    F opened_product(0);
    Digest opening_binding{};
    if (!mpc.Open(product_share, &opened_product, &opening_binding) ||
        opening_binding == Digest{})
        return false;
    *consistency_bound =
        opened_product == lhs_secret * rhs_secret &&
        backend.relation_reference_count() > 0 &&
        backend.vss_local_prove_count() > 0;
    return true;
}

bool run_robust_opening_and_coin_selftest(
    int rank, int world_size,
    bool* corrected_open, bool* excessive_fault_rejected,
    bool* public_coin_bound, bool* degree_reduction_bound,
    bool* random_sharing_bound) {
    if (!corrected_open || !excessive_fault_rejected || !public_coin_bound ||
        !degree_reduction_bound || !random_sharing_bound || world_size < 3)
        return false;
    const int threshold = (world_size - 1) / 3;
    ReferenceShamirMpc mpc(rank, world_size, threshold);
    if (!mpc.valid() || !mpc.robust_opening_available()) return false;

    const int dealer = 0;
    const F secret(0x12345, 0x6789);
    std::vector<F> plaintext;
    if (rank == dealer) plaintext = {secret};
    std::vector<F> shares;
    if (!mpc.ShareVectorFromDealer(dealer, plaintext, &shares) ||
        shares.size() != 1)
        return false;

    F one_fault_share = shares.front();
    if (rank < threshold) one_fault_share += F(17, 9);
    F corrected(0);
    Digest corrected_binding{};
    const bool corrected_ok =
        mpc.Open(one_fault_share, &corrected, &corrected_binding);
    *corrected_open = corrected_ok && corrected == secret &&
        corrected_binding != Digest{};

    F too_many_faults_share = shares.front();
    if (rank <= threshold) too_many_faults_share += F(23, 11);
    F should_not_open(0);
    Digest rejected_binding{};
    const bool excessive_opened =
        mpc.Open(too_many_faults_share, &should_not_open, &rejected_binding);
    *excessive_fault_rejected = !excessive_opened;

    Digest seed{};
    Digest coin_binding{};
    *public_coin_bound =
        mpc.JointPublicSeed(&seed, &coin_binding) &&
        seed != Digest{} && coin_binding != Digest{};

    F random_test_share(0);
    Digest random_test_binding{};
    *random_sharing_bound = mpc.RandomSharedField(
        &random_test_share, &random_test_binding) &&
        random_test_binding != Digest{} &&
        mpc.detectable_degree_reduction_available();


    const F lhs_secret(5, 2);
    const F rhs_secret(9, 4);
    std::vector<F> product_plaintext;
    if (rank == dealer) product_plaintext = {lhs_secret, rhs_secret};
    std::vector<F> product_inputs;
    if (!mpc.ShareVectorFromDealer(
            dealer, product_plaintext, &product_inputs) ||
        product_inputs.size() != 2)
        return false;
    F product_share(0);
    Digest multiplication_binding{};
    const bool multiplication_ok = mpc.Multiply(
        product_inputs[0], product_inputs[1], &product_share,
        &multiplication_binding);
    F opened_product(0);
    Digest product_opening_binding{};
    const bool product_opened = multiplication_ok &&
        mpc.Open(product_share, &opened_product, &product_opening_binding);
    *degree_reduction_bound = product_opened &&
        opened_product == lhs_secret * rhs_secret &&
        multiplication_binding != Digest{} &&
        product_opening_binding != Digest{} &&
        mpc.detectable_degree_reduction_available();
    return true;
}
bool run_authenticated_passive_opening_selftest(
    int rank, int world_size, bool* exercised, bool* opening_bound) {
    if (!exercised || !opening_bound || world_size < 2 ||
        rank < 0 || rank >= world_size)
        return false;
    *exercised = false;
    *opening_bound = false;
    // n=3,t=1 is the smallest valid 2t<n configuration outside 3t<n.
    // Other world sizes leave this targeted branch not applicable.
    if (world_size != 3) {
        *opening_bound = true;
        return true;
    }
    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready()) {
        *opening_bound = true;
        return true;
    }
    *exercised = true;
    constexpr int threshold = 1;
    if (2 * threshold >= world_size || 3 * threshold < world_size)
        return false;
    ReferenceShamirMpc mpc(rank, world_size, threshold);
    const uint64_t sid = 0x4155544850415353ULL; // AUTHPASS
    const CheckpointId checkpoint = 0x4155544850410001ULL;
    if (!mpc.SetAuthenticatedTransport(&exchange, sid, checkpoint) ||
        !mpc.authenticated_transport_available() ||
        mpc.robust_opening_available())
        return false;
    const F secret(37, 11);
    std::vector<F> dealer_plaintext;
    if (rank == 0) dealer_plaintext = {secret};
    std::vector<F> local_shares;
    if (!mpc.ShareVectorFromDealer(
            0, dealer_plaintext, &local_shares) ||
        local_shares.size() != 1)
        return false;
    F opened(0);
    Digest opening_binding{};
    if (!mpc.Open(local_shares.front(), &opened, &opening_binding))
        return false;
    *opening_bound = opened == secret && opening_binding != Digest{};
    return true;
}

bool run_authenticated_session_transport_selftest(
    int rank, int world_size, bool* exercised, bool* transport_bound) {
    if (!exercised || !transport_bound || world_size < 3) return false;
    *exercised = false;
    *transport_bound = false;
    auto fail = [&](const char* stage) {
        if (rank == 0)
            std::cerr << "[PVIA][auth-session-selftest] failed-stage="
                      << stage << "\n";
        return false;
    };
    AuthenticatedMpcExchange exchange(rank, world_size);
    if (!exchange.production_authenticated_ready()) {
        *transport_bound = true;
        return true;
    }
    *exercised = true;
    const int threshold = (world_size - 1) / 3;
    if (3 * threshold >= world_size) return fail("threshold");
    const uint64_t sid = 0x4155544853455353ULL; // AUTHSESS
    const CheckpointId checkpoint = 0x4155544853450001ULL;
    SelfTestMultiplicationConsistencyBackend multiplication_backend;
    ReferenceShamirAuditSession session(
        sid, checkpoint, rank, world_size, threshold,
        nullptr, &multiplication_backend, &exchange);
    if (!session.authenticated_transport_enabled() ||
        session.authenticated_transport_capability_binding() !=
            exchange.ProductionCapabilityBinding())
        return fail("transport-install");
    const F challenge(11, 2);
    std::vector<F> state(8);
    for (size_t i = 0; i < state.size(); ++i)
        state[i] = F(static_cast<long long>(700 + i),
                     static_cast<long long>(900 + i));
    std::vector<F> output;
    if (!recompute_fold_rs_output(state, challenge, &output))
        return fail("recompute");
    std::vector<F> owner_state;
    std::vector<F> owner_output;
    if (rank == 0) {
        owner_state = state;
        owner_output = output;
    }
    const OperationRef ref{0U, 0x41555448534d4b31ULL};
    const Digest statement = hash_words({
        sid, checkpoint, ref.owner, ref.object_id,
        0x4155544853544d54ULL});
    if (!session.RegisterFoldOperation(
            0U, ref, challenge, hash_field_vector(state),
            hash_field_vector(output), statement,
            owner_state, owner_output))
        return fail("register");
    if (!session.SealRegistration())
        return fail("seal-registration");
    const Digest session_transport =
        session.authenticated_transport_transcript_binding();
    if (session_transport == Digest{})
        return fail("registration-transport-binding");
    const ReferenceShamirBatchResult batch = session.BatchCheck();
    const Digest final_session_transport =
        session.authenticated_transport_transcript_binding();
    *transport_bound = batch.available && batch.clean &&
        batch.operation_count == 1 &&
        batch.registration_binding != Digest{} &&
        batch.public_coin_transcript_binding != Digest{} &&
        batch.challenge_binding != Digest{} &&
        batch.multiplication_consistency_binding != Digest{} &&
        batch.opening_transcript_binding != Digest{} &&
        final_session_transport != Digest{} &&
        final_session_transport != session_transport;
    if (!*transport_bound && rank == 0) {
        std::cerr << "[PVIA][auth-session-selftest] available="
                  << (batch.available ? 1 : 0)
                  << " clean=" << (batch.clean ? 1 : 0)
                  << " operations=" << batch.operation_count
                  << " registration="
                  << (batch.registration_binding != Digest{} ? 1 : 0)
                  << " public-coin="
                  << (batch.public_coin_transcript_binding != Digest{} ? 1 : 0)
                  << " challenge="
                  << (batch.challenge_binding != Digest{} ? 1 : 0)
                  << " opening="
                  << (batch.opening_transcript_binding != Digest{} ? 1 : 0)
                  << " session-transport-before="
                  << (session_transport != Digest{} ? 1 : 0)
                  << " session-transport-after="
                  << (final_session_transport != Digest{} ? 1 : 0)
                  << " multiplication="
                  << (batch.multiplication_consistency_binding != Digest{} ? 1 : 0)
                  << " session-transport-evolved="
                  << (final_session_transport != session_transport ? 1 : 0)
                  << "\n";
    }
    return true;
}

bool run_preactivated_subset_localization_selftest(
    int rank, int world_size, bool* subset_bound,
    bool* localization_bound) {
    if (!subset_bound || !localization_bound || world_size < 3)
        return false;
    *subset_bound = false;
    *localization_bound = false;
    if (world_size < 4) {
        *subset_bound = true;
        *localization_bound = true;
        return true;
    }

    const int threshold = (world_size - 1) / 3;
    if (3 * threshold >= world_size) return false;
    const uint64_t sid = 0x5052454143545355ULL; // PREACTSU
    const CheckpointId checkpoint = 0x5052454143540001ULL;
    AuthenticatedMpcExchange exchange(rank, world_size);
    const AuthenticatedMpcExchange* exchange_ptr =
        exchange.production_authenticated_ready() ? &exchange : nullptr;
    ReferenceShamirAuditSession session(
        sid, checkpoint, rank, world_size, threshold,
        nullptr, nullptr, exchange_ptr);

    const uint32_t faulty_owner = static_cast<uint32_t>(world_size / 2);
    std::vector<OperationRef> refs;
    std::vector<F> post_activation_shadow;
    for (int owner = 0; owner < world_size; ++owner) {
        const F challenge(owner + 11);
        std::vector<F> state(8);
        for (size_t i = 0; i < state.size(); ++i)
            state[i] = F(500 * (owner + 1) + static_cast<int>(i) + 1);
        std::vector<F> output;
        if (!recompute_fold_rs_output(state, challenge, &output))
            return false;
        if (static_cast<uint32_t>(owner) == faulty_owner && !output.empty())
            output.front() += F(1);

        const OperationRef ref{
            static_cast<uint32_t>(owner),
            static_cast<uint64_t>(0x6000 + owner)};
        refs.push_back(ref);
        std::vector<F> owner_state;
        std::vector<F> owner_output;
        if (rank == owner) {
            owner_state = state;
            owner_output = output;
            post_activation_shadow = output;
        }
        const Digest statement = hash_words({
            sid, checkpoint, static_cast<u64>(owner), ref.object_id,
            0x5052454143545354ULL}); // PREACTST
        if (!session.RegisterFoldOperation(
                static_cast<uint32_t>(owner), ref, challenge,
                hash_field_vector(state), hash_field_vector(output),
                statement, owner_state, owner_output))
            return false;
    }
    if (!session.SealRegistration()) return false;

    // Mutate the caller-owned shadow after activation. Subsequent checks must
    // depend only on session-resident Shamir/VSS shares, never on this source.
    for (F& value : post_activation_shadow) value = F(0);

    auto domain_for = [&](const std::vector<OperationRef>& subset,
                          u64 depth, u64 side) {
        std::vector<u64> words = {
            0x505245535542444dULL, sid, checkpoint, depth, side,
            static_cast<u64>(subset.size())}; // PRESUBDM
        for (const OperationRef& ref : subset) {
            words.push_back(ref.owner);
            words.push_back(ref.object_id);
        }
        return hash_words(words);
    };

    const ReferenceShamirSubsetResult full = session.BatchCheckSubset(
        refs, domain_for(refs, 0, 2), 1);
    const uint32_t clean_owner = (faulty_owner + 1U) %
        static_cast<uint32_t>(world_size);
    const std::vector<OperationRef> clean_single = {
        refs[static_cast<size_t>(clean_owner)]};
    const ReferenceShamirSubsetResult clean = session.BatchCheckSubset(
        clean_single, domain_for(clean_single, 0, 3), 2);
    *subset_bound = full.available && !full.clean &&
        full.subset_binding != Digest{} && full.challenge_binding != Digest{} &&
        full.opening_transcript_binding != Digest{} &&
        clean.available && clean.clean && clean.subset_binding != Digest{};
    if (!*subset_bound) return true;

    std::vector<OperationRef> candidates = refs;
    uint32_t depth = 0;
    uint64_t round_tag = 10;
    while (candidates.size() > 1) {
        const size_t mid = candidates.size() / 2;
        std::vector<OperationRef> left(
            candidates.begin(), candidates.begin() + mid);
        const ReferenceShamirSubsetResult left_result =
            session.BatchCheckSubset(
                left, domain_for(left, depth, 0), round_tag++);
        if (!left_result.available) return true;
        if (!left_result.clean) {
            candidates = std::move(left);
        } else {
            std::vector<OperationRef> right(
                candidates.begin() + mid, candidates.end());
            const ReferenceShamirSubsetResult right_result =
                session.BatchCheckSubset(
                    right, domain_for(right, depth, 1), round_tag++);
            if (!right_result.available || right_result.clean) return true;
            candidates = std::move(right);
        }
        ++depth;
    }
    const OperationRef expected{
        faulty_owner, static_cast<uint64_t>(0x6000 + faulty_owner)};
    *localization_bound = candidates.size() == 1 &&
        candidates.front() == expected;
    return true;
}

} // namespace
bool run_reference_shamir_mpc_selftest(int rank, int world_size) {
    bool authenticated_passive_open_exercised = false;
    bool authenticated_passive_open_bound = false;
    const bool authenticated_passive_open_run =
        run_authenticated_passive_opening_selftest(
            rank, world_size, &authenticated_passive_open_exercised,
            &authenticated_passive_open_bound);
    bool authenticated_transport_exercised = false;
    bool authenticated_transport_bound = false;
    const bool authenticated_transport_run =
        run_authenticated_session_transport_selftest(
            rank, world_size, &authenticated_transport_exercised,
            &authenticated_transport_bound);
    const bool equivocation_evidence_bound =
        !authenticated_transport_exercised ||
        run_authenticated_mpc_equivocation_evidence_selftest(
            rank, world_size);
    const bool robust_abort_output_bound =
        !authenticated_transport_exercised ||
        run_robust_audit_abort_output_selftest(rank, world_size);

    ReferenceShamirBatchResult clean;
    ReferenceShamirBatchResult faulty;
    const bool clean_run = run_one_reference_session(
        rank, world_size, false, &clean);
    const bool faulty_run = run_one_reference_session(
        rank, world_size, true, &faulty);
    bool preactivated_subset_bound = false;
    bool preactivated_localization_bound = false;
    const bool preactivated_subset_run =
        run_preactivated_subset_localization_selftest(
            rank, world_size, &preactivated_subset_bound,
            &preactivated_localization_bound);

    bool corrected_open = false;
    bool excessive_fault_rejected = false;
    bool public_coin_bound = false;
    bool degree_reduction_bound = false;
    bool random_sharing_bound = false;
    const bool robust_primitives_run =
        run_robust_opening_and_coin_selftest(
            rank, world_size, &corrected_open,
            &excessive_fault_rejected, &public_coin_bound,
            &degree_reduction_bound, &random_sharing_bound);

    bool registration_consistency_bound = false;
    const bool registration_consistency_run =
        run_registration_consistency_wiring_selftest(
            rank, world_size, &registration_consistency_bound);

    bool multiplication_consistency_bound = false;
    bool missing_multiplication_backend_rejected = false;
    const bool multiplication_consistency_run =
        run_multiplication_consistency_wiring_selftest(
            rank, world_size, &multiplication_consistency_bound,
            &missing_multiplication_backend_rejected);

    ReferenceShamirBatchResult strong_clean;
    ReferenceShamirBatchResult strong_faulty;
    const bool strong_clean_run = run_strong_batch_once(
        rank, world_size, false, &strong_clean);
    const bool strong_faulty_run = run_strong_batch_once(
        rank, world_size, true, &strong_faulty);
    const bool strong_batch_bound =
        strong_clean_run && strong_clean.clean &&
        strong_clean.multiplication_consistency_binding != Digest{} &&
        strong_faulty_run && !strong_faulty.clean &&
        strong_faulty.multiplication_consistency_binding != Digest{};

    const bool batch_transcripts_bound =
        clean.public_coin_transcript_binding != Digest{} &&
        clean.challenge_binding != Digest{} &&
        clean.opening_transcript_binding != Digest{} &&
        faulty.public_coin_transcript_binding != Digest{} &&
        faulty.opening_transcript_binding != Digest{};
    int local_ok = authenticated_passive_open_run &&
        authenticated_passive_open_bound && authenticated_transport_run &&
        authenticated_transport_bound && equivocation_evidence_bound &&
        robust_abort_output_bound &&
        clean_run && clean.available && clean.clean &&
        faulty_run && faulty.available && !faulty.clean &&
        preactivated_subset_run && preactivated_subset_bound &&
        preactivated_localization_bound &&
        batch_transcripts_bound && robust_primitives_run &&
        corrected_open && excessive_fault_rejected && public_coin_bound &&
        degree_reduction_bound && random_sharing_bound &&
        registration_consistency_run && registration_consistency_bound &&
        multiplication_consistency_run && multiplication_consistency_bound &&
        missing_multiplication_backend_rejected && strong_batch_bound ? 1 : 0;
    int global_ok = 0;
    MPI_Allreduce(&local_ok, &global_ok, 1, MPI_INT, MPI_MIN,
                  MPI_COMM_WORLD);
    if (rank == 0) {
        const int threshold = world_size > 0 ? (world_size - 1) / 2 : -1;
        const int robust_threshold = world_size > 0 ? (world_size - 1) / 3 : -1;
        std::cout << "[PVIA][shamir-mpc-selftest] threshold=" << threshold
                  << " robust-threshold=" << robust_threshold
                  << " operations=" << clean.operation_count
                  << " auth-passive-open="
                  << (world_size != 3
                          ? "N/A"
                          : (authenticated_passive_open_exercised
                                 ? (authenticated_passive_open_bound ? "BOUND" : "FAIL")
                                 : "UNANCHORED-SKIP"))
                  << " auth-transport="
                  << (authenticated_transport_exercised
                          ? (authenticated_transport_bound ? "BOUND" : "FAIL")
                          : "UNANCHORED-SKIP")
                  << " equivocation-evidence="
                  << (authenticated_transport_exercised
                          ? (equivocation_evidence_bound ? "BOUND" : "FAIL")
                          : "UNANCHORED-SKIP")
                  << " robust-abort="
                  << (authenticated_transport_exercised
                          ? (robust_abort_output_bound ? "BOUND" : "FAIL")
                          : "UNANCHORED-SKIP")
                  << " clean=" << (clean.clean ? "PASS" : "FAIL")
                  << " mismatch=" << (!faulty.clean ? "DETECTED" : "MISSED")
                  << " preactivated-subset="
                  << (preactivated_subset_bound ? "BOUND" : "FAIL")
                  << " preactivated-localization="
                  << (preactivated_localization_bound ? "BOUND" : "FAIL")
                  << " robust-open=" << (corrected_open ? "PASS" : "FAIL")
                  << " over-threshold="
                  << (excessive_fault_rejected ? "REJECTED" : "ACCEPTED")
                  << " public-coin=" << (public_coin_bound ? "BOUND" : "FAIL")
                  << " degree-reduction="
                  << (degree_reduction_bound ? "VSS-BOUND" : "FAIL")
                  << " random-sharing="
                  << (random_sharing_bound ? "VSS-BOUND" : "FAIL")
                  << " registration-consistency="
                  << (registration_consistency_bound ? "BOUND" : "FAIL")
                  << " multiplication-consistency="
                  << (multiplication_consistency_bound ? "BOUND" : "FAIL")
                  << " missing-mul-backend="
                  << (missing_multiplication_backend_rejected
                          ? "REJECTED" : "ACCEPTED")
                  << " strong-batch="
                  << (strong_clean.clean ? "BOUND" : "FAIL")
                  << " strong-mismatch="
                  << (strong_faulty_run && !strong_faulty.clean
                          ? "DETECTED" : "MISSED")
                  << " transcript="
                  << (batch_transcripts_bound ? "BOUND" : "MISSING")
                  << " result=" << (global_ok ? "PASS" : "FAIL")
                  << "\n";
    }
    return global_ok != 0;
}

} // namespace pvia
