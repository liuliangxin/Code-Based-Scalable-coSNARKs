#include "AccountabilitySignature.hpp"

#include <cstring>
#include <vector>

namespace pvia {
namespace {

constexpr u64 SIGNATURE_CAP_DOMAIN =
    0x5056534947434150ULL; // PVSIGCAP

void append_digest(
    const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}

} // namespace

Digest compute_accountability_signature_capability_binding(
    const AccountabilitySignatureCapabilities& c) {
    std::vector<u64> words = {
        SIGNATURE_CAP_DOMAIN,
        c.available ? 1ULL : 0ULL,
        c.scheme_id,
        c.post_quantum ? 1ULL : 0ULL,
        c.hash_based ? 1ULL : 0ULL,
        c.deterministic ? 1ULL : 0ULL,
        c.variable_length_signature ? 1ULL : 0ULL,
        static_cast<u64>(c.private_key_bytes),
        static_cast<u64>(c.public_key_bytes),
        static_cast<u64>(c.signature_bytes)
    };
    append_digest(c.implementation_binding, &words);
    return hash_words(words);
}

bool validate_accountability_signature_capabilities(
    const AccountabilitySignatureCapabilities& c) {
    if (!c.available || c.scheme_id == 0 ||
        c.private_key_bytes == 0 || c.public_key_bytes == 0 ||
        c.implementation_binding == Digest{})
        return false;
    if (!c.variable_length_signature && c.signature_bytes == 0)
        return false;
    return c.capability_binding != Digest{} &&
        c.capability_binding ==
            compute_accountability_signature_capability_binding(c);
}

bool accountability_signature_satisfies(
    const AccountabilitySignatureCapabilities& c,
    const AccountabilitySignatureRequirements& r) {
    if (!validate_accountability_signature_capabilities(c))
        return false;
    if (r.require_post_quantum && !c.post_quantum)
        return false;
    if (r.require_hash_based && !c.hash_based)
        return false;
    if (!r.allow_variable_length_signature &&
        c.variable_length_signature)
        return false;
    return true;
}

} // namespace pvia
