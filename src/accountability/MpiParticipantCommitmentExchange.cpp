#include "MpiParticipantCommitmentExchange.hpp"

#include <cstring>
#include <mpi.h>

namespace pvia {
namespace {

void digest_to_words(const Digest& digest, uint64_t* out) {
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(&out[i], digest.bytes.data() + 8 * i, 8);
}

Digest words_to_digest(const uint64_t* words) {
    Digest digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[i], 8);
    return digest;
}

} // namespace
std::vector<ParticipantResidualCommitment>
MpiParticipantCommitmentExchange::AllGather(
    const ParticipantResidualCommitment& local,
    int rank,
    int world_size) {
    if (world_size <= 0 || rank < 0 || rank >= world_size ||
        local.owner != static_cast<uint32_t>(rank))
        return {};

    constexpr int WORDS = 14;
    uint64_t send[WORDS]{};
    send[0] = local.owner;
    send[1] = static_cast<uint64_t>(local.handle_count);
    digest_to_words(local.descriptor_digest, &send[2]);
    digest_to_words(local.local_commitment_root, &send[6]);
    digest_to_words(local.authentication_commitment, &send[10]);

    std::vector<uint64_t> recv(static_cast<size_t>(world_size) * WORDS, 0);
    MPI_Allgather(send, WORDS, MPI_UINT64_T,
                  recv.data(), WORDS, MPI_UINT64_T, MPI_COMM_WORLD);
    std::vector<ParticipantResidualCommitment> out;
    out.reserve(static_cast<size_t>(world_size));
    for (int i = 0; i < world_size; ++i) {
        const uint64_t* words = &recv[static_cast<size_t>(i) * WORDS];
        ParticipantResidualCommitment item;
        item.owner = static_cast<uint32_t>(words[0]);
        item.handle_count = static_cast<size_t>(words[1]);
        item.descriptor_digest = words_to_digest(&words[2]);
        item.local_commitment_root = words_to_digest(&words[6]);
        item.authentication_commitment = words_to_digest(&words[10]);
        out.push_back(item);
    }
    return out;
}

} // namespace pvia
