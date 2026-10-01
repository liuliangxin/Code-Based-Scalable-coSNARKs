#include "ReferenceLinearSharingProvenance.hpp"
#include "MultiplicationConsistencyProviderAbiC.h"

#include <cstring>
#include <limits>
#include <utility>

namespace pvia {
namespace {

constexpr u64 LINEAR_BIND_DOMAIN = PVIA_MC_LINEAR_BINDING_DOMAIN;
constexpr u64 LINEAR_WITNESS_DOMAIN = PVIA_MC_LINEAR_WITNESS_DOMAIN;

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

Digest read_digest(const std::vector<u64>& words, size_t offset) {
    Digest digest{};
    if (offset > words.size() || words.size() - offset < 4) return digest;
    for (size_t i = 0; i < 4; ++i)
        std::memcpy(digest.bytes.data() + 8 * i, &words[offset + i], 8);
    return digest;
}
bool source_local_value(
    const ReferenceLinearSharingSource& source, F* value) {
    if (!value || !validate_reference_vss_local_witness(source.local_witness) ||
        source.sharing_binding == Digest{} ||
        source.local_witness.transcript_binding != source.sharing_binding ||
        source.element_coefficients.size() !=
            source.local_witness.element_count)
        return false;
    const size_t dimension =
        static_cast<size_t>(source.local_witness.threshold + 1);
    F sum(0);
    for (size_t i = 0; i < source.element_coefficients.size(); ++i) {
        const size_t field_index = i * dimension;
        const size_t word_index = 2 * field_index;
        if (word_index + 1 >= source.local_witness.local_row_words.size())
            return false;
        const F local_element(
            static_cast<long long>(
                source.local_witness.local_row_words[word_index]),
            static_cast<long long>(
                source.local_witness.local_row_words[word_index + 1]));
        sum += source.element_coefficients[i] * local_element;
    }
    *value = sum;
    return true;
}

} // namespace
Digest compute_reference_linear_sharing_binding(
    const std::vector<ReferenceLinearSharingSource>& sources) {
    if (sources.empty()) return Digest{};
    std::vector<u64> words = {
        LINEAR_BIND_DOMAIN, static_cast<u64>(sources.size())};
    for (const auto& source : sources) {
        if (source.sharing_binding == Digest{} ||
            source.element_coefficients.empty())
            return Digest{};
        append_digest(source.sharing_binding, &words);
        words.push_back(static_cast<u64>(source.element_coefficients.size()));
        for (const F& coefficient : source.element_coefficients) {
            words.push_back(coefficient.real);
            words.push_back(coefficient.img);
        }
    }
    return hash_words(words);
}

bool build_reference_linear_sharing_provenance(
    std::vector<ReferenceLinearSharingSource> sources,
    ReferenceLinearSharingProvenance* provenance) {
    if (!provenance || sources.empty()) return false;
    F local_share(0);
    for (const auto& source : sources) {
        F source_value(0);
        if (!source_local_value(source, &source_value)) return false;
        local_share += source_value;
    }
    const Digest binding = compute_reference_linear_sharing_binding(sources);
    if (binding == Digest{}) return false;
    ReferenceLinearSharingProvenance built;
    built.available = true;
    built.local_share = local_share;
    built.sources = std::move(sources);
    built.binding = binding;
    *provenance = std::move(built);
    return true;
}

bool validate_reference_linear_sharing_provenance(
    const ReferenceLinearSharingProvenance& provenance) {
    if (!provenance.available || provenance.sources.empty() ||
        provenance.binding == Digest{})
        return false;
    F local_share(0);
    for (const auto& source : provenance.sources) {
        F source_value(0);
        if (!source_local_value(source, &source_value)) return false;
        local_share += source_value;
    }
    return local_share == provenance.local_share &&
        provenance.binding ==
            compute_reference_linear_sharing_binding(provenance.sources);
}
std::vector<u64> encode_reference_linear_sharing_provenance(
    const ReferenceLinearSharingProvenance& provenance) {
    if (!validate_reference_linear_sharing_provenance(provenance)) return {};
    std::vector<u64> words = {
        LINEAR_WITNESS_DOMAIN,
        provenance.local_share.real,
        provenance.local_share.img,
        static_cast<u64>(provenance.sources.size())};
    append_digest(provenance.binding, &words);
    for (const auto& source : provenance.sources) {
        append_digest(source.sharing_binding, &words);
        words.push_back(static_cast<u64>(source.element_coefficients.size()));
        for (const F& coefficient : source.element_coefficients) {
            words.push_back(coefficient.real);
            words.push_back(coefficient.img);
        }
        const std::vector<u64> local_words =
            encode_reference_vss_local_witness(source.local_witness);
        if (local_words.empty()) return {};
        words.push_back(static_cast<u64>(local_words.size()));
        words.insert(words.end(), local_words.begin(), local_words.end());
    }
    return words;
}
bool decode_reference_linear_sharing_provenance(
    const std::vector<u64>& words,
    ReferenceLinearSharingProvenance* provenance) {
    if (!provenance || words.size() < PVIA_MC_LINEAR_FIXED_WORDS ||
        words[0] != LINEAR_WITNESS_DOMAIN ||
        words[1] >= PVIA_MC_FIELD_MODULUS ||
        words[2] >= PVIA_MC_FIELD_MODULUS ||
        words[3] == 0 ||
        words[3] > static_cast<u64>(std::numeric_limits<size_t>::max()))
        return false;
    ReferenceLinearSharingProvenance decoded;
    decoded.available = true;
    decoded.local_share = F(
        static_cast<long long>(words[1]),
        static_cast<long long>(words[2]));
    const size_t source_count = static_cast<size_t>(words[3]);
    decoded.binding = read_digest(words, 4);
    size_t offset = PVIA_MC_LINEAR_FIXED_WORDS;
    decoded.sources.reserve(source_count);
    for (size_t source_index = 0;
         source_index < source_count; ++source_index) {
        if (offset > words.size() || words.size() - offset < 5)
            return false;
        ReferenceLinearSharingSource source;
        source.sharing_binding = read_digest(words, offset);
        offset += 4;
        const u64 coefficient_count_u64 = words[offset++];
        if (coefficient_count_u64 == 0 ||
            coefficient_count_u64 >
                static_cast<u64>(std::numeric_limits<size_t>::max()))
            return false;
        const size_t coefficient_count =
            static_cast<size_t>(coefficient_count_u64);
        if (coefficient_count > (words.size() - offset) / 2)
            return false;
        source.element_coefficients.reserve(coefficient_count);
        for (size_t i = 0; i < coefficient_count; ++i) {
            if (words[offset] >= PVIA_MC_FIELD_MODULUS ||
                words[offset + 1] >= PVIA_MC_FIELD_MODULUS)
                return false;
            source.element_coefficients.emplace_back(
                static_cast<long long>(words[offset]),
                static_cast<long long>(words[offset + 1]));
            offset += 2;
        }
        if (offset >= words.size()) return false;
        const u64 local_count_u64 = words[offset++];
        if (local_count_u64 == 0 ||
            local_count_u64 > static_cast<u64>(words.size() - offset))
            return false;
        const size_t local_count = static_cast<size_t>(local_count_u64);
        std::vector<u64> local_words(
            words.begin() + static_cast<std::ptrdiff_t>(offset),
            words.begin() + static_cast<std::ptrdiff_t>(offset + local_count));
        offset += local_count;
        if (!decode_reference_vss_local_witness(
                local_words, &source.local_witness))
            return false;
        decoded.sources.push_back(std::move(source));
    }
    if (offset != words.size()) return false;
    if (!validate_reference_linear_sharing_provenance(decoded)) return false;
    *provenance = std::move(decoded);
    return true;
}

} // namespace pvia
