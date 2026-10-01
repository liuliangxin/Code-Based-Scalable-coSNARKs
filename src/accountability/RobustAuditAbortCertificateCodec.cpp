#include "RobustAuditAbortCertificateCodec.hpp"

#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>

namespace pvia {
namespace {

constexpr u64 CERT_MAGIC = 0x5056524142434552ULL; // PVRABCER
constexpr u64 CERT_VERSION = 1ULL;
constexpr size_t MAX_CERT_OPERATIONS = 1ULL << 16;
constexpr size_t MAX_CERT_KERNELS = 1ULL << 12;
constexpr size_t MAX_CERT_PUBLIC_KEYS = 1ULL << 16;
constexpr unsigned long long MAX_CERT_FILE_WORDS = 1ULL << 20;

void append_digest(const Digest& digest, std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, digest.bytes.data() + 8 * i, 8);
        words->push_back(word);
    }
}
void append_signature(
    const std::array<uint8_t, 64>& signature,
    std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 8; ++i) {
        u64 word = 0;
        std::memcpy(&word, signature.data() + 8 * i, 8);
        words->push_back(word);
    }
}

void append_public_key(
    const std::array<uint8_t, 32>& public_key,
    std::vector<u64>* words) {
    if (!words) return;
    for (size_t i = 0; i < 4; ++i) {
        u64 word = 0;
        std::memcpy(&word, public_key.data() + 8 * i, 8);
        words->push_back(word);
    }
}

class WordReader {
public:
    explicit WordReader(const std::vector<u64>& words) : words_(words) {}

    template <typename UInt>
    bool ReadU64(UInt* out) {
        static_assert(std::is_integral<UInt>::value &&
                          std::is_unsigned<UInt>::value,
                      "ReadU64 requires an unsigned integral destination");
        if (!out || pos_ >= words_.size()) return false;
        const u64 word = words_[pos_++];
        if (word > static_cast<u64>(std::numeric_limits<UInt>::max()))
            return false;
        *out = static_cast<UInt>(word);
        return true;
    }

    bool ReadU32(uint32_t* out) {
        u64 word = 0;
        if (!out || !ReadU64(&word) ||
            word > std::numeric_limits<uint32_t>::max())
            return false;
        *out = static_cast<uint32_t>(word);
        return true;
    }

    bool ReadBool(bool* out) {
        u64 word = 0;
        if (!out || !ReadU64(&word) || word > 1) return false;
        *out = word != 0;
        return true;
    }

    bool ReadDigest(Digest* out) {
        if (!out || remaining() < 4) return false;
        for (size_t i = 0; i < 4; ++i)
            std::memcpy(out->bytes.data() + 8 * i, &words_[pos_++], 8);
        return true;
    }
    bool ReadSignature(std::array<uint8_t, 64>* out) {
        if (!out || remaining() < 8) return false;
        for (size_t i = 0; i < 8; ++i)
            std::memcpy(out->data() + 8 * i, &words_[pos_++], 8);
        return true;
    }

    bool ReadPublicKey(std::array<uint8_t, 32>* out) {
        if (!out || remaining() < 4) return false;
        for (size_t i = 0; i < 4; ++i)
            std::memcpy(out->data() + 8 * i, &words_[pos_++], 8);
        return true;
    }

    size_t remaining() const { return words_.size() - pos_; }
    bool done() const { return pos_ == words_.size(); }

private:
    const std::vector<u64>& words_;
    size_t pos_ = 0;
};

bool activation_is_empty(const RobustAuditActivation& activation) {
    return !activation.available && activation.sid == 0 &&
        activation.checkpoint == 0 && activation.registered_operations == 0 &&
        activation.checkpoint_root == Digest{} &&
        activation.checkpoint_binding == Digest{} &&
        activation.capability_binding == Digest{} &&
        activation.authenticated_channel_activation_binding == Digest{} &&
        activation.delivery_activation_binding == Digest{} &&
        activation.registration_consistency_binding == Digest{} &&
        activation.activation_transcript_binding == Digest{} &&
        activation.activation_binding == Digest{};
}

void append_capabilities(
    const RobustAuditCapabilities& c, std::vector<u64>* words) {
    words->insert(words->end(), {
        c.available ? 1ULL : 0ULL, c.protocol_id,
        static_cast<u64>(c.security_level),
        c.malicious_secure ? 1ULL : 0ULL,
        c.authenticated_channels ? 1ULL : 0ULL,
        c.publicly_identifiable_abort ? 1ULL : 0ULL,
        c.guaranteed_output_delivery ? 1ULL : 0ULL,
        c.activation_before_failure ? 1ULL : 0ULL,
        c.private_witness_retention ? 1ULL : 0ULL,
        c.detectable_input_sharing ? 1ULL : 0ULL,
        c.public_registration_consistency ? 1ULL : 0ULL,
        c.robust_opening ? 1ULL : 0ULL,
        c.commit_reveal_public_coin ? 1ULL : 0ULL,
        c.detectable_degree_reduction ? 1ULL : 0ULL,
        c.detectable_random_sharing ? 1ULL : 0ULL,
        c.malicious_multiplication_consistency ? 1ULL : 0ULL,
        c.packed_sharing ? 1ULL : 0ULL,
        static_cast<u64>(c.corruption_threshold),
        static_cast<u64>(c.supported_kernels.size())});
    for (AuditRelationKernel kernel : c.supported_kernels)
        words->push_back(static_cast<u64>(kernel));
    append_digest(c.authenticated_channel_capability_binding, words);
    append_digest(c.identifiable_abort_capability_binding, words);
    append_digest(c.delivery_capability_binding, words);
    append_digest(c.registration_consistency_capability_binding, words);
    append_digest(c.multiplication_consistency_capability_binding, words);
    append_digest(c.implementation_binding, words);
    append_digest(c.capability_binding, words);
}

bool read_capabilities(WordReader* reader, RobustAuditCapabilities* c) {
    if (!reader || !c) return false;
    uint32_t security_level = 0;
    if (!reader->ReadBool(&c->available) || !reader->ReadU64(&c->protocol_id) ||
        !reader->ReadU32(&security_level) ||
        !reader->ReadBool(&c->malicious_secure) ||
        !reader->ReadBool(&c->authenticated_channels) ||
        !reader->ReadBool(&c->publicly_identifiable_abort) ||
        !reader->ReadBool(&c->guaranteed_output_delivery) ||
        !reader->ReadBool(&c->activation_before_failure) ||
        !reader->ReadBool(&c->private_witness_retention) ||
        !reader->ReadBool(&c->detectable_input_sharing) ||
        !reader->ReadBool(&c->public_registration_consistency) ||
        !reader->ReadBool(&c->robust_opening) ||
        !reader->ReadBool(&c->commit_reveal_public_coin) ||
        !reader->ReadBool(&c->detectable_degree_reduction) ||
        !reader->ReadBool(&c->detectable_random_sharing) ||
        !reader->ReadBool(&c->malicious_multiplication_consistency) ||
        !reader->ReadBool(&c->packed_sharing) ||
        !reader->ReadU32(&c->corruption_threshold))
        return false;
    c->security_level = static_cast<RobustAuditSecurityLevel>(security_level);
    u64 kernel_count = 0;
    if (!reader->ReadU64(&kernel_count) || kernel_count == 0 ||
        kernel_count > MAX_CERT_KERNELS || kernel_count > reader->remaining())
        return false;
    c->supported_kernels.clear();
    c->supported_kernels.reserve(static_cast<size_t>(kernel_count));
    for (u64 i = 0; i < kernel_count; ++i) {
        uint32_t kernel = 0;
        if (!reader->ReadU32(&kernel)) return false;
        c->supported_kernels.push_back(static_cast<AuditRelationKernel>(kernel));
    }
    return reader->ReadDigest(&c->authenticated_channel_capability_binding) &&
        reader->ReadDigest(&c->identifiable_abort_capability_binding) &&
        reader->ReadDigest(&c->delivery_capability_binding) &&
        reader->ReadDigest(&c->registration_consistency_capability_binding) &&
        reader->ReadDigest(&c->multiplication_consistency_capability_binding) &&
        reader->ReadDigest(&c->implementation_binding) &&
        reader->ReadDigest(&c->capability_binding);
}

void append_activation(
    const RobustAuditActivation& activation, std::vector<u64>* words) {
    words->insert(words->end(), {
        activation.available ? 1ULL : 0ULL,
        activation.sid, activation.checkpoint,
        static_cast<u64>(activation.registered_operations)});
    append_digest(activation.checkpoint_root, words);
    append_digest(activation.checkpoint_binding, words);
    append_digest(activation.capability_binding, words);
    append_digest(activation.authenticated_channel_activation_binding, words);
    append_digest(activation.delivery_activation_binding, words);
    append_digest(activation.registration_consistency_binding, words);
    append_digest(activation.activation_transcript_binding, words);
    append_digest(activation.activation_binding, words);
}

bool read_activation(WordReader* reader, RobustAuditActivation* activation) {
    if (!reader || !activation) return false;
    u64 registered = 0;
    if (!reader->ReadBool(&activation->available) ||
        !reader->ReadU64(&activation->sid) ||
        !reader->ReadU64(&activation->checkpoint) ||
        !reader->ReadU64(&registered) ||
        registered > static_cast<u64>(std::numeric_limits<size_t>::max()))
        return false;
    activation->registered_operations = static_cast<size_t>(registered);
    return reader->ReadDigest(&activation->checkpoint_root) &&
        reader->ReadDigest(&activation->checkpoint_binding) &&
        reader->ReadDigest(&activation->capability_binding) &&
        reader->ReadDigest(
            &activation->authenticated_channel_activation_binding) &&
        reader->ReadDigest(&activation->delivery_activation_binding) &&
        reader->ReadDigest(&activation->registration_consistency_binding) &&
        reader->ReadDigest(&activation->activation_transcript_binding) &&
        reader->ReadDigest(&activation->activation_binding);
}

void append_equivocation(
    const AuthenticatedMpcEquivocationEvidence& evidence,
    std::vector<u64>* words) {
    words->insert(words->end(), {
        evidence.available ? 1ULL : 0ULL,
        static_cast<u64>(evidence.kind),
        evidence.context.protocol_domain, evidence.context.sid,
        evidence.context.checkpoint, evidence.context.round,
        evidence.context.sequence, evidence.context.message_kind,
        static_cast<u64>(evidence.sender),
        static_cast<u64>(evidence.receiver),
        evidence.first_payload_word_count});
    append_digest(evidence.first_payload_binding, words);
    append_signature(evidence.first_signature, words);
    words->push_back(evidence.second_payload_word_count);
    append_digest(evidence.second_payload_binding, words);
    append_signature(evidence.second_signature, words);
    words->push_back(static_cast<u64>(evidence.public_keys.size()));
    for (const auto& public_key : evidence.public_keys)
        append_public_key(public_key, words);
    append_digest(evidence.registry_commitment, words);
    append_digest(evidence.evidence_binding, words);
}

bool read_equivocation(
    WordReader* reader, AuthenticatedMpcEquivocationEvidence* evidence) {
    if (!reader || !evidence) return false;
    uint32_t kind = 0;
    if (!reader->ReadBool(&evidence->available) ||
        !reader->ReadU32(&kind) ||
        !reader->ReadU64(&evidence->context.protocol_domain) ||
        !reader->ReadU64(&evidence->context.sid) ||
        !reader->ReadU64(&evidence->context.checkpoint) ||
        !reader->ReadU64(&evidence->context.round) ||
        !reader->ReadU64(&evidence->context.sequence) ||
        !reader->ReadU64(&evidence->context.message_kind) ||
        !reader->ReadU32(&evidence->sender) ||
        !reader->ReadU32(&evidence->receiver) ||
        !reader->ReadU64(&evidence->first_payload_word_count) ||
        !reader->ReadDigest(&evidence->first_payload_binding) ||
        !reader->ReadSignature(&evidence->first_signature) ||
        !reader->ReadU64(&evidence->second_payload_word_count) ||
        !reader->ReadDigest(&evidence->second_payload_binding) ||
        !reader->ReadSignature(&evidence->second_signature))
        return false;
    evidence->kind = static_cast<AuthenticatedMpcAbortEvidenceKind>(kind);
    u64 key_count = 0;
    if (!reader->ReadU64(&key_count) || key_count == 0 ||
        key_count > MAX_CERT_PUBLIC_KEYS ||
        key_count > reader->remaining() / 4)
        return false;
    evidence->public_keys.clear();
    evidence->public_keys.reserve(static_cast<size_t>(key_count));
    for (u64 i = 0; i < key_count; ++i) {
        std::array<uint8_t, 32> public_key{};
        if (!reader->ReadPublicKey(&public_key)) return false;
        evidence->public_keys.push_back(public_key);
    }
    return reader->ReadDigest(&evidence->registry_commitment) &&
        reader->ReadDigest(&evidence->evidence_binding);
}

void append_output(
    const RobustAuditAbortOutput& output, std::vector<u64>* words) {
    words->insert(words->end(), {
        output.available ? 1ULL : 0ULL,
        output.publicly_verifiable ? 1ULL : 0ULL,
        static_cast<u64>(output.stage), output.sid, output.checkpoint,
        static_cast<u64>(output.accused)});
    append_digest(output.checkpoint_root, words);
    append_digest(output.checkpoint_binding, words);
    append_digest(output.capability_binding, words);
    append_digest(output.authenticated_channel_capability_binding, words);
    append_digest(output.activation_binding, words);
    append_digest(output.external_registry_anchor, words);
    append_equivocation(output.equivocation, words);
    append_digest(output.abort_transcript_binding, words);
    append_digest(output.abort_binding, words);
}

bool read_output(WordReader* reader, RobustAuditAbortOutput* output) {
    if (!reader || !output) return false;
    uint32_t stage = 0;
    if (!reader->ReadBool(&output->available) ||
        !reader->ReadBool(&output->publicly_verifiable) ||
        !reader->ReadU32(&stage) ||
        !reader->ReadU64(&output->sid) ||
        !reader->ReadU64(&output->checkpoint) ||
        !reader->ReadU32(&output->accused) ||
        !reader->ReadDigest(&output->checkpoint_root) ||
        !reader->ReadDigest(&output->checkpoint_binding) ||
        !reader->ReadDigest(&output->capability_binding) ||
        !reader->ReadDigest(
            &output->authenticated_channel_capability_binding) ||
        !reader->ReadDigest(&output->activation_binding) ||
        !reader->ReadDigest(&output->external_registry_anchor) ||
        !read_equivocation(reader, &output->equivocation) ||
        !reader->ReadDigest(&output->abort_transcript_binding) ||
        !reader->ReadDigest(&output->abort_binding))
        return false;
    output->stage = static_cast<RobustAuditAbortStage>(stage);
    return true;
}

} // namespace

bool verify_robust_audit_abort_certificate(
    const RobustAuditAbortCertificate& certificate,
    const Digest& expected_registry_anchor) {
    if (expected_registry_anchor == Digest{} ||
        !certificate.checkpoint.sealed || certificate.checkpoint.id == 0 ||
        certificate.checkpoint.phase == Phase::UNKNOWN ||
        certificate.checkpoint.root == Digest{} ||
        !production_ready_identifiable_abort_capabilities(
            certificate.capabilities) ||
        certificate.output.external_registry_anchor !=
            expected_registry_anchor)
        return false;

    const RobustAuditActivation* activation = nullptr;
    if (certificate.has_activation) {
        if (!validate_robust_audit_activation(
                certificate.checkpoint, certificate.capabilities,
                certificate.activation))
            return false;
        activation = &certificate.activation;
    } else if (!activation_is_empty(certificate.activation)) {
        return false;
    }

    if ((certificate.output.stage == RobustAuditAbortStage::ACTIVATION &&
         certificate.has_activation) ||
        (certificate.output.stage == RobustAuditAbortStage::EXECUTION &&
         !certificate.has_activation) ||
        certificate.output.stage == RobustAuditAbortStage::UNKNOWN)
        return false;
    const size_t public_key_count =
        certificate.output.equivocation.public_keys.size();
    if (public_key_count == 0 ||
        public_key_count > static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;
    return validate_robust_audit_abort_output(
        certificate.checkpoint, certificate.capabilities, activation,
        certificate.output, expected_registry_anchor,
        static_cast<int>(public_key_count));
}

std::vector<u64> encode_robust_audit_abort_certificate(
    const RobustAuditAbortCertificate& certificate) {
    // Internal consistency is checked against the anchor carried by the
    // artifact. This does not establish trust in that anchor.
    if (!verify_robust_audit_abort_certificate(
            certificate, certificate.output.external_registry_anchor) ||
        certificate.checkpoint.operations.size() > MAX_CERT_OPERATIONS ||
        certificate.capabilities.supported_kernels.size() > MAX_CERT_KERNELS ||
        certificate.output.equivocation.public_keys.size() >
            MAX_CERT_PUBLIC_KEYS)
        return {};

    std::vector<u64> words = {CERT_MAGIC, CERT_VERSION};
    words.insert(words.end(), {
        certificate.checkpoint.id,
        static_cast<u64>(certificate.checkpoint.phase),
        static_cast<u64>(certificate.checkpoint.round),
        static_cast<u64>(certificate.checkpoint.generation),
        certificate.checkpoint.sealed ? 1ULL : 0ULL,
        static_cast<u64>(certificate.checkpoint.operations.size())});
    for (const OperationRef& ref : certificate.checkpoint.operations) {
        words.push_back(static_cast<u64>(ref.owner));
        words.push_back(ref.object_id);
    }
    append_digest(certificate.checkpoint.root, &words);
    append_capabilities(certificate.capabilities, &words);
    words.push_back(certificate.has_activation ? 1ULL : 0ULL);
    if (certificate.has_activation)
        append_activation(certificate.activation, &words);
    append_output(certificate.output, &words);
    return words;
}

bool decode_robust_audit_abort_certificate(
    const std::vector<u64>& words,
    RobustAuditAbortCertificate* certificate) {
    if (!certificate || words.size() < 2 ||
        words.size() > MAX_CERT_FILE_WORDS)
        return false;
    WordReader reader(words);
    u64 magic = 0;
    u64 version = 0;
    if (!reader.ReadU64(&magic) || !reader.ReadU64(&version) ||
        magic != CERT_MAGIC || version != CERT_VERSION)
        return false;

    RobustAuditAbortCertificate out;
    uint32_t phase = 0;
    uint32_t round = 0;
    uint32_t generation = 0;
    u64 operation_count = 0;
    if (!reader.ReadU64(&out.checkpoint.id) ||
        !reader.ReadU32(&phase) ||
        !reader.ReadU32(&round) ||
        !reader.ReadU32(&generation) ||
        !reader.ReadBool(&out.checkpoint.sealed) ||
        !reader.ReadU64(&operation_count) ||
        operation_count > MAX_CERT_OPERATIONS ||
        operation_count > reader.remaining() / 2)
        return false;
    out.checkpoint.phase = static_cast<Phase>(phase);
    out.checkpoint.round = round;
    out.checkpoint.generation = generation;
    out.checkpoint.operations.clear();
    out.checkpoint.operations.reserve(static_cast<size_t>(operation_count));
    for (u64 i = 0; i < operation_count; ++i) {
        OperationRef ref;
        if (!reader.ReadU32(&ref.owner) || !reader.ReadU64(&ref.object_id))
            return false;
        out.checkpoint.operations.push_back(ref);
    }
    if (!reader.ReadDigest(&out.checkpoint.root) ||
        !read_capabilities(&reader, &out.capabilities) ||
        !reader.ReadBool(&out.has_activation))
        return false;
    if (out.has_activation &&
        !read_activation(&reader, &out.activation))
        return false;
    if (!read_output(&reader, &out.output) || !reader.done())
        return false;

    // This only proves internal self-consistency. Trust still requires an
    // externally supplied anchor in verify_robust_audit_abort_certificate().
    if (!verify_robust_audit_abort_certificate(
            out, out.output.external_registry_anchor))
        return false;
    *certificate = std::move(out);
    return true;
}

bool verify_encoded_robust_audit_abort_certificate(
    const std::vector<u64>& words,
    const Digest& expected_registry_anchor) {
    RobustAuditAbortCertificate certificate;
    return decode_robust_audit_abort_certificate(words, &certificate) &&
        verify_robust_audit_abort_certificate(
            certificate, expected_registry_anchor);
}

bool write_robust_audit_abort_certificate_file(
    const std::string& path,
    const RobustAuditAbortCertificate& certificate) {
    if (path.empty()) return false;
    const std::vector<u64> words =
        encode_robust_audit_abort_certificate(certificate);
    if (words.empty()) return false;
    std::ofstream output(path, std::ios::out | std::ios::trunc);
    if (!output) return false;
    output << "PVIA_ROBUST_ABORT_CERT_V1\n" << words.size() << "\n";
    output << std::hex << std::setfill('0');
    for (u64 word : words)
        output << std::setw(16) << word << "\n";
    return output.good();
}

bool read_robust_audit_abort_certificate_file(
    const std::string& path,
    std::vector<u64>* encoded_certificate) {
    if (!encoded_certificate || path.empty()) return false;
    std::ifstream input(path);
    if (!input) return false;
    std::string line;
    if (!std::getline(input, line) ||
        line != "PVIA_ROBUST_ABORT_CERT_V1")
        return false;
    if (!std::getline(input, line)) return false;
    size_t pos = 0;
    unsigned long long count = 0;
    try {
        count = std::stoull(line, &pos, 10);
    } catch (...) {
        return false;
    }
    if (pos != line.size() || count == 0 ||
        count > MAX_CERT_FILE_WORDS)
        return false;
    std::vector<u64> words;
    words.reserve(static_cast<size_t>(count));
    for (unsigned long long i = 0; i < count; ++i) {
        if (!std::getline(input, line) || line.size() != 16) return false;
        pos = 0;
        unsigned long long word = 0;
        try {
            word = std::stoull(line, &pos, 16);
        } catch (...) {
            return false;
        }
        if (pos != line.size()) return false;
        words.push_back(static_cast<u64>(word));
    }
    while (std::getline(input, line))
        if (!line.empty()) return false;
    RobustAuditAbortCertificate decoded;
    if (!decode_robust_audit_abort_certificate(words, &decoded))
        return false;
    *encoded_certificate = std::move(words);
    return true;
}

bool parse_robust_audit_registry_anchor_hex(
    const std::string& text, Digest* anchor) {
    if (!anchor || text.size() != 64) return false;
    Digest out;
    const auto hex = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < out.bytes.size(); ++i) {
        const int hi = hex(text[2 * i]);
        const int lo = hex(text[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    if (out == Digest{}) return false;
    *anchor = out;
    return true;
}

} // namespace pvia
