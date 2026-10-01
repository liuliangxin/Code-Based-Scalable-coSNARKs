#include "JointPackedPreprocessing.hpp"
#include "ProtocolTrafficMetrics.hpp"
#include "../utils.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

namespace pvia {
namespace {

constexpr u64 JOINT_PACKED_BIND_DOMAIN = 0x50564a5041434b44ULL;

bool secure_random_fields(size_t count, std::vector<F>* out) {
    if (!out) return false;
    out->clear();
    if (count == 0) return true;
    if (count > std::numeric_limits<size_t>::max() / 2) return false;
    std::vector<u64> words(count * 2);
    unsigned char* bytes = reinterpret_cast<unsigned char*>(words.data());
    const size_t total = words.size() * sizeof(u64);
    size_t offset = 0;
    constexpr size_t chunk_limit = 1u << 20;
    while (offset < total) {
        const size_t chunk = std::min(chunk_limit, total - offset);
        if (RAND_bytes(bytes + offset, static_cast<int>(chunk)) != 1)
            return false;
        offset += chunk;
    }
    out->resize(count);
    for (size_t i = 0; i < count; ++i) {
        (*out)[i] = F(
            static_cast<long long>(words[2*i] % F::mod),
            static_cast<long long>(words[2*i+1] % F::mod));
    }
    return true;
}

void append_digest_words(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8*i, 8);
        words->push_back(word);
    }
}

bool power_of_two(int value) {
    return value > 0 && (value & (value - 1)) == 0;
}

} // namespace

bool generate_joint_packed_random_share(
    size_t share_count, int world_size, int k, int packed_width,
    uint64_t domain, std::vector<F>* local_share,
    JointPackedPreprocessingResult* result, MPI_Comm comm) {
    if (result) *result = JointPackedPreprocessingResult{};
    if (!local_share || share_count == 0 || domain == 0) return false;
    ExperimentControlTrafficScope traffic_scope(
        ExperimentControlTrafficKind::PREPROCESSING);

    int rank = -1;
    int actual_world = 0;
    MPI_Comm_rank(comm, &rank);
    MPI_Comm_size(comm, &actual_world);
    const bool local_shape_ok =
        actual_world == world_size && world_size >= 4 &&
        rank >= 0 && rank < world_size &&
        k > 0 && packed_width > k &&
        packed_width * 2 == world_size &&
        k * 4 == world_size &&
        power_of_two(packed_width) && power_of_two(2 * world_size) &&
        share_count <= static_cast<size_t>(std::numeric_limits<int>::max() / 2);
    int local_ok = local_shape_ok ? 1 : 0;
    int global_ok = 0;
    MPI_Allreduce(&local_ok, &global_ok, 1, MPI_INT, MPI_MIN, comm);
    record_control_allreduce(sizeof(int), world_size);
    if (!global_ok) return false;

    if (share_count > std::numeric_limits<size_t>::max() /
                          static_cast<size_t>(packed_width))
        return false;
    std::vector<F> local_material;
    if (!secure_random_fields(
            share_count * static_cast<size_t>(packed_width),
            &local_material))
        return false;

    if (share_count > std::numeric_limits<size_t>::max() /
                          static_cast<size_t>(world_size))
        return false;
    std::vector<F> send_fields(
        share_count * static_cast<size_t>(world_size), F(0));
    const int packed_log = static_cast<int>(std::log2(packed_width));
    const int eval_log = static_cast<int>(std::log2(2 * world_size));
    for (size_t block = 0; block < share_count; ++block) {
        std::vector<F> polynomial(static_cast<size_t>(packed_width));
        const size_t base = block * static_cast<size_t>(packed_width);
        for (int j = 0; j < packed_width; ++j)
            polynomial[static_cast<size_t>(j)] =
                local_material[base + static_cast<size_t>(j)];
        fft(polynomial, packed_log, true);
        polynomial.resize(static_cast<size_t>(2 * world_size), F(0));
        fft(polynomial, eval_log, false);
        for (int recipient = 0; recipient < world_size; ++recipient) {
            send_fields[static_cast<size_t>(recipient) * share_count + block] =
                polynomial[static_cast<size_t>(2 * recipient + 1)];
        }
    }

    if (send_fields.size() > std::numeric_limits<size_t>::max() / 2)
        return false;
    std::vector<u64> send_words(send_fields.size() * 2);
    for (size_t i = 0; i < send_fields.size(); ++i) {
        send_words[2*i] = send_fields[i].real;
        send_words[2*i+1] = send_fields[i].img;
    }
    std::vector<u64> recv_words(send_words.size(), 0);
    const size_t words_per_peer = 2 * share_count;
    if (words_per_peer > static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;
    MPI_Alltoall(
        send_words.data(), static_cast<int>(words_per_peer), MPI_UINT64_T,
        recv_words.data(), static_cast<int>(words_per_peer), MPI_UINT64_T,
        comm);
    record_control_all_peer_exchange(
        words_per_peer * sizeof(u64), world_size);

    local_share->assign(share_count, F(0));
    for (int contributor = 0; contributor < world_size; ++contributor) {
        const size_t peer_base =
            static_cast<size_t>(contributor) * words_per_peer;
        for (size_t block = 0; block < share_count; ++block) {
            const u64 real = recv_words[peer_base + 2*block] % F::mod;
            const u64 imag = recv_words[peer_base + 2*block + 1] % F::mod;
            (*local_share)[block] += F(
                static_cast<long long>(real),
                static_cast<long long>(imag));
        }
    }

    const Digest share_digest = hash_field_vector(*local_share);
    std::vector<u64> binding_words = {
        JOINT_PACKED_BIND_DOMAIN, domain,
        static_cast<u64>(world_size), static_cast<u64>(k),
        static_cast<u64>(packed_width), static_cast<u64>(share_count),
        static_cast<u64>(rank)};
    append_digest_words(share_digest, &binding_words);
    const Digest binding = hash_words(binding_words);
    if (binding == Digest{}) return false;

    if (result) {
        result->ok = true;
        result->share_count = share_count;
        result->contributors = world_size;
        result->local_binding = binding;
    }
    return true;
}

} // namespace pvia
