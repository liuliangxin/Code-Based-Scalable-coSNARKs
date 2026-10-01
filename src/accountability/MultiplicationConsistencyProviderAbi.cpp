#include "MultiplicationConsistencyProviderAbi.hpp"

#include <cstring>
#include <limits>

namespace pvia {
namespace {

constexpr u64 STATEMENT_ABI_DOMAIN = PVIA_MC_STATEMENT_ABI_DOMAIN;
constexpr u64 WITNESS_ABI_DOMAIN = PVIA_MC_WITNESS_ABI_DOMAIN;
constexpr u64 CAPABILITY_ABI_DOMAIN = PVIA_MC_CAPABILITY_ABI_DOMAIN;

void append_digest_words(const Digest& digest, std::vector<uint64_t>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

Digest digest_from_words(const std::vector<uint64_t>& words, size_t offset) {
    Digest digest{};
    if (offset > words.size() || words.size() - offset < 4)
        return digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(
            digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}

bool valid_flag(u64 value) {
    return value == 0 || value == 1;
}

} // namespace

std::vector<uint64_t> encode_multiplication_consistency_statement_abi(
    const MultiplicationConsistencyStatement& statement) {
    std::vector<uint64_t> words = {
        STATEMENT_ABI_DOMAIN,
        MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_VERSION,
        statement.sid,
        statement.checkpoint,
        statement.multiplication_id,
        static_cast<u64>(statement.dealer)};
    append_digest_words(statement.lhs_sharing_binding, &words);
    append_digest_words(statement.rhs_sharing_binding, &words);
    append_digest_words(statement.output_sharing_binding, &words);
    append_digest_words(statement.context_binding, &words);
    append_digest_words(statement.statement_binding, &words);
    return words;
}

bool decode_multiplication_consistency_statement_abi(
    const std::vector<uint64_t>& words,
    MultiplicationConsistencyStatement* statement) {
    if (!statement || words.size() != PVIA_MC_STATEMENT_WORDS ||
        words[0] != STATEMENT_ABI_DOMAIN ||
        words[1] != MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_VERSION ||
        words[5] > std::numeric_limits<uint32_t>::max())
        return false;
    MultiplicationConsistencyStatement decoded;
    decoded.sid = words[2];
    decoded.checkpoint = words[3];
    decoded.multiplication_id = words[4];
    decoded.dealer = static_cast<uint32_t>(words[5]);
    decoded.lhs_sharing_binding = digest_from_words(words, 6);
    decoded.rhs_sharing_binding = digest_from_words(words, 10);
    decoded.output_sharing_binding = digest_from_words(words, 14);
    decoded.context_binding = digest_from_words(words, 18);
    decoded.statement_binding = digest_from_words(words, 22);
    if (!validate_multiplication_consistency_statement(decoded))
        return false;
    *statement = decoded;
    return true;
}

std::vector<uint64_t> encode_multiplication_consistency_witness_abi(
    const MultiplicationConsistencyWitness& witness) {
    std::vector<uint64_t> words = {
        WITNESS_ABI_DOMAIN,
        MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_VERSION,
        witness.lhs_share.real,
        witness.lhs_share.img,
        witness.rhs_share.real,
        witness.rhs_share.img,
        witness.product_value.real,
        witness.product_value.img,
        static_cast<u64>(witness.lhs_sharing_witness_words.size()),
        static_cast<u64>(witness.rhs_sharing_witness_words.size()),
        static_cast<u64>(witness.output_sharing_witness_words.size())};
    words.insert(
        words.end(),
        witness.lhs_sharing_witness_words.begin(),
        witness.lhs_sharing_witness_words.end());
    words.insert(
        words.end(),
        witness.rhs_sharing_witness_words.begin(),
        witness.rhs_sharing_witness_words.end());
    words.insert(
        words.end(),
        witness.output_sharing_witness_words.begin(),
        witness.output_sharing_witness_words.end());
    return words;
}

bool decode_multiplication_consistency_witness_abi(
    const std::vector<uint64_t>& words,
    MultiplicationConsistencyWitness* witness) {
    if (!witness || words.size() < PVIA_MC_WITNESS_HEADER_WORDS ||
        words[0] != WITNESS_ABI_DOMAIN ||
        words[1] != MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_VERSION ||
        words[2] >= PVIA_MC_FIELD_MODULUS ||
        words[3] >= PVIA_MC_FIELD_MODULUS ||
        words[4] >= PVIA_MC_FIELD_MODULUS ||
        words[5] >= PVIA_MC_FIELD_MODULUS ||
        words[6] >= PVIA_MC_FIELD_MODULUS ||
        words[7] >= PVIA_MC_FIELD_MODULUS)
        return false;
    if (words[8] > std::numeric_limits<size_t>::max() ||
        words[9] > std::numeric_limits<size_t>::max() ||
        words[10] > std::numeric_limits<size_t>::max())
        return false;
    const size_t lhs_n = static_cast<size_t>(words[8]);
    const size_t rhs_n = static_cast<size_t>(words[9]);
    const size_t out_n = static_cast<size_t>(words[10]);
    if (lhs_n > words.size() || rhs_n > words.size() ||
        out_n > words.size())
        return false;
    if (lhs_n > std::numeric_limits<size_t>::max() - rhs_n ||
        lhs_n + rhs_n >
            std::numeric_limits<size_t>::max() - out_n)
        return false;
    const size_t payload_n = lhs_n + rhs_n + out_n;
    if (payload_n != words.size() - PVIA_MC_WITNESS_HEADER_WORDS)
        return false;

    MultiplicationConsistencyWitness decoded;
    decoded.lhs_share.real = static_cast<u64>(words[2]);
    decoded.lhs_share.img = static_cast<u64>(words[3]);
    decoded.rhs_share.real = static_cast<u64>(words[4]);
    decoded.rhs_share.img = static_cast<u64>(words[5]);
    decoded.product_value.real = static_cast<u64>(words[6]);
    decoded.product_value.img = static_cast<u64>(words[7]);
    size_t pos = PVIA_MC_WITNESS_HEADER_WORDS;
    decoded.lhs_sharing_witness_words.assign(
        words.begin() + pos, words.begin() + pos + lhs_n);
    pos += lhs_n;
    decoded.rhs_sharing_witness_words.assign(
        words.begin() + pos, words.begin() + pos + rhs_n);
    pos += rhs_n;
    decoded.output_sharing_witness_words.assign(
        words.begin() + pos, words.end());
    *witness = std::move(decoded);
    return true;
}

std::vector<uint64_t> encode_multiplication_consistency_capabilities_abi(
    const MultiplicationConsistencyCapabilities& capabilities) {
    std::vector<uint64_t> words = {
        CAPABILITY_ABI_DOMAIN,
        MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_VERSION,
        capabilities.available ? 1ULL : 0ULL,
        capabilities.malicious_sound ? 1ULL : 0ULL,
        capabilities.zero_knowledge ? 1ULL : 0ULL,
        capabilities.binds_input_sharings ? 1ULL : 0ULL,
        capabilities.binds_output_sharing ? 1ULL : 0ULL,
        capabilities.protocol_id};
    append_digest_words(capabilities.relation_binding, &words);
    append_digest_words(capabilities.implementation_binding, &words);
    append_digest_words(capabilities.capability_binding, &words);
    return words;
}

bool decode_multiplication_consistency_capabilities_abi(
    const std::vector<uint64_t>& words,
    MultiplicationConsistencyCapabilities* capabilities) {
    if (!capabilities || words.size() != PVIA_MC_CAPABILITY_WORDS ||
        words[0] != CAPABILITY_ABI_DOMAIN ||
        words[1] != MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_VERSION ||
        !valid_flag(words[2]) || !valid_flag(words[3]) ||
        !valid_flag(words[4]) || !valid_flag(words[5]) ||
        !valid_flag(words[6]))
        return false;
    MultiplicationConsistencyCapabilities decoded;
    decoded.available = words[2] != 0;
    decoded.malicious_sound = words[3] != 0;
    decoded.zero_knowledge = words[4] != 0;
    decoded.binds_input_sharings = words[5] != 0;
    decoded.binds_output_sharing = words[6] != 0;
    decoded.protocol_id = words[PVIA_MC_CAP_PROTOCOL_ID_INDEX];
    decoded.relation_binding =
        digest_from_words(words, PVIA_MC_CAP_RELATION_BINDING_INDEX);
    decoded.implementation_binding =
        digest_from_words(words, PVIA_MC_CAP_IMPLEMENTATION_BINDING_INDEX);
    decoded.capability_binding =
        digest_from_words(words, PVIA_MC_CAP_CAPABILITY_BINDING_INDEX);
    if (!validate_multiplication_consistency_capabilities(decoded))
        return false;
    *capabilities = decoded;
    return true;
}

} // namespace pvia
