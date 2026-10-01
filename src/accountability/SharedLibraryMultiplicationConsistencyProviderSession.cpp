#include "SharedLibraryMultiplicationConsistencyProviderSession.hpp"
#include "MultiplicationConsistencyProviderAbiHelpers.h"

#include <dlfcn.h>

#include <cstring>
#include <limits>
#include <utility>
#include <vector>

namespace pvia {
namespace {

constexpr size_t MAX_PROVIDER_WORDS = 1ULL << 24;

template <typename Fn>
Fn load_symbol(void* handle, const char* name) {
    return reinterpret_cast<Fn>(dlsym(handle, name));
}

void append_digest_as_words(
    const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

} // namespace

SharedLibraryMultiplicationConsistencyProviderSession::
SharedLibraryMultiplicationConsistencyProviderSession(
    std::string library_path,
    uint32_t expected_proof_system_id)
    : library_path_(std::move(library_path)),
      expected_proof_system_id_(expected_proof_system_id) {}

SharedLibraryMultiplicationConsistencyProviderSession::
~SharedLibraryMultiplicationConsistencyProviderSession() {
    Close();
}

bool SharedLibraryMultiplicationConsistencyProviderSession::Load() {
    if (loaded()) return true;
    Close();
    if (library_path_.empty() || expected_proof_system_id_ == 0) {
        error_ = "provider path or proof-system id is missing";
        return false;
    }

    handle_ = dlopen(library_path_.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle_) {
        const char* detail = dlerror();
        error_ = detail ? detail : "unable to load provider library";
        Close();
        return false;
    }

    version_fn_ = load_symbol<MultiplicationConsistencyAbiVersionFn>(
        handle_, MULTIPLICATION_CONSISTENCY_ABI_VERSION_SYMBOL);
    capabilities_fn_ =
        load_symbol<MultiplicationConsistencyAbiCapabilitiesFn>(
            handle_, MULTIPLICATION_CONSISTENCY_ABI_CAPABILITIES_SYMBOL);
    prove_fn_ = load_symbol<MultiplicationConsistencyAbiProveFn>(
        handle_, MULTIPLICATION_CONSISTENCY_ABI_PROVE_SYMBOL);
    verify_fn_ = load_symbol<MultiplicationConsistencyAbiVerifyFn>(
        handle_, MULTIPLICATION_CONSISTENCY_ABI_VERIFY_SYMBOL);
    if (!version_fn_ || !capabilities_fn_ || !prove_fn_ || !verify_fn_) {
        error_ = "provider library is missing one or more required ABI symbols";
        Close();
        return false;
    }
    if (version_fn_() != MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_VERSION) {
        error_ = "provider ABI version does not match";
        Close();
        return false;
    }

    size_t count = 0;
    if (capabilities_fn_(nullptr, &count) != 1 ||
        count == 0 || count > MAX_PROVIDER_WORDS) {
        error_ = "provider capabilities size query failed";
        Close();
        return false;
    }
    std::vector<uint64_t> words(count);
    size_t actual = count;
    if (capabilities_fn_(words.data(), &actual) != 1 ||
        actual != count ||
        !decode_multiplication_consistency_capabilities_abi(
            words, &capabilities_) ||
        !production_ready_multiplication_consistency_capabilities(
            capabilities_)) {
        error_ = "provider capabilities are not accepted";
        Close();
        return false;
    }

    MultiplicationConsistencyProviderCallbacks callbacks;
    callbacks.prove =
        [this](
            const MultiplicationConsistencyStatement& statement,
            const MultiplicationConsistencyWitness& witness) {
            return Prove(statement, witness);
        };
    callbacks.verify =
        [this](
            const MultiplicationConsistencyStatement& statement,
            const MultiplicationConsistencyProofArtifact& proof) {
            return Verify(statement, proof);
        };
    session_ =
        std::make_unique<ExternalMultiplicationConsistencyProviderSession>(
            capabilities_, expected_proof_system_id_, std::move(callbacks));
    if (!session_->adapter_ready()) {
        error_ = "provider adapter is not ready";
        Close();
        return false;
    }

    error_.clear();
    return true;
}

bool SharedLibraryMultiplicationConsistencyProviderSession::
CollectiveProviderAgreement(
    int rank, int world_size, MPI_Comm comm) const {
    if (!loaded() || rank < 0 || world_size <= 0 || rank >= world_size)
        return false;

    std::vector<u64> local = {
        static_cast<u64>(MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_VERSION),
        static_cast<u64>(expected_proof_system_id_),
        capabilities_.protocol_id};
    append_digest_as_words(capabilities_.capability_binding, &local);
    append_digest_as_words(capabilities_.relation_binding, &local);
    append_digest_as_words(capabilities_.implementation_binding, &local);

    std::vector<u64> gathered(
        local.size() * static_cast<size_t>(world_size), 0);
    MPI_Allgather(
        local.data(), static_cast<int>(local.size()), MPI_UINT64_T,
        gathered.data(), static_cast<int>(local.size()), MPI_UINT64_T,
        comm);
    for (int participant = 1; participant < world_size; ++participant) {
        const size_t offset =
            static_cast<size_t>(participant) * local.size();
        for (size_t i = 0; i < local.size(); ++i) {
            if (gathered[offset + i] != gathered[i])
                return false;
        }
    }
    return true;
}

bool SharedLibraryMultiplicationConsistencyProviderSession::Activate(
    int rank, int world_size, MPI_Comm comm) {
    int local_loaded = Load() ? 1 : 0;
    int all_loaded = 0;
    MPI_Allreduce(
        &local_loaded, &all_loaded, 1, MPI_INT, MPI_MIN, comm);
    if (!all_loaded)
        return false;
    if (!CollectiveProviderAgreement(rank, world_size, comm)) {
        error_ = "provider identity differs across participants";
        return false;
    }
    if (!session_ || !session_->Activate(rank, world_size, comm)) {
        error_ = "provider distributed acceptance did not complete";
        return false;
    }
    error_.clear();
    return true;
}

void SharedLibraryMultiplicationConsistencyProviderSession::Reset() {
    if (session_)
        session_->Reset();
}

MultiplicationConsistencyProofArtifact
SharedLibraryMultiplicationConsistencyProviderSession::Prove(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyWitness& witness) const {
    MultiplicationConsistencyProofArtifact proof;
    if (!prove_fn_ ||
        !validate_multiplication_consistency_statement(statement))
        return proof;

    const auto statement_words =
        encode_multiplication_consistency_statement_abi(statement);
    const auto witness_words =
        encode_multiplication_consistency_witness_abi(witness);
    pvia_mc_statement_view c_statement{};
    pvia_mc_witness_view c_witness{};
    if (!pvia_mc_parse_statement(
            statement_words.data(), statement_words.size(),
            &c_statement) ||
        !pvia_mc_parse_witness(
            witness_words.data(), witness_words.size(),
            &c_witness) ||
        !pvia_mc_validate_witness_payloads(&c_witness))
        return proof;
    size_t proof_count = 0;
    if (prove_fn_(
            statement_words.data(), statement_words.size(),
            witness_words.data(), witness_words.size(),
            nullptr, &proof_count) != 1 ||
        proof_count == 0 || proof_count > MAX_PROVIDER_WORDS)
        return proof;

    std::vector<uint64_t> proof_words(proof_count);
    size_t actual = proof_count;
    if (prove_fn_(
            statement_words.data(), statement_words.size(),
            witness_words.data(), witness_words.size(),
            proof_words.data(), &actual) != 1 ||
        actual != proof_count)
        return MultiplicationConsistencyProofArtifact{};
    const std::vector<u64> internal_proof_words(
        proof_words.begin(), proof_words.end());
    if (!decode_multiplication_consistency_proof_artifact(
            internal_proof_words, &proof))
        return MultiplicationConsistencyProofArtifact{};
    return proof;
}

bool SharedLibraryMultiplicationConsistencyProviderSession::Verify(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyProofArtifact& proof) const {
    if (!verify_fn_ ||
        !validate_multiplication_consistency_statement(statement) ||
        !validate_multiplication_consistency_proof_artifact(
            statement, proof))
        return false;
    const auto statement_words =
        encode_multiplication_consistency_statement_abi(statement);
    const auto internal_proof_words =
        encode_multiplication_consistency_proof_artifact(proof);
    const std::vector<uint64_t> proof_words(
        internal_proof_words.begin(), internal_proof_words.end());
    return verify_fn_(
        statement_words.data(), statement_words.size(),
        proof_words.data(), proof_words.size()) == 1;
}

void SharedLibraryMultiplicationConsistencyProviderSession::Close() {
    session_.reset();
    version_fn_ = nullptr;
    capabilities_fn_ = nullptr;
    prove_fn_ = nullptr;
    verify_fn_ = nullptr;
    capabilities_ = MultiplicationConsistencyCapabilities{};
    if (handle_) {
        dlclose(handle_);
        handle_ = nullptr;
    }
}

} // namespace pvia
