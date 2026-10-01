#ifndef PVIA_MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_C_H
#define PVIA_MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stable external ABI for multiplication-consistency providers.
 *
 * All arrays are sequences of uint64_t words. Canonical bindings are BLAKE3-256
 * over the little-endian byte encoding of the listed word sequence. A digest
 * occupies four consecutive uint64_t words (32 bytes).
 */
#define PVIA_MC_ABI_VERSION UINT32_C(2)
#define PVIA_MC_DIGEST_WORDS ((size_t)4)

#define PVIA_MC_FIELD_MODULUS UINT64_C(2305843009213693951)
#define PVIA_MC_FIELD_COMPONENT_WORDS ((size_t)2)
#define PVIA_MC_FIELD_EXTENSION_I_SQUARED_IS_NEG_ONE UINT64_C(1)

/*
 * A field element is encoded as two canonical limbs (real, imaginary), each
 * strictly smaller than PVIA_MC_FIELD_MODULUS. Arithmetic is over
 * F_p[i] / (i^2 + 1):
 *   (a + b*i)(c + d*i) =
 *     (a*c - b*d) + (a*d + b*c)*i  mod p.
 */

typedef struct pvia_mc_field_element {
    uint64_t real;
    uint64_t imaginary;
} pvia_mc_field_element;

static inline int pvia_mc_field_is_canonical(
    pvia_mc_field_element value) {
    return value.real < PVIA_MC_FIELD_MODULUS &&
           value.imaginary < PVIA_MC_FIELD_MODULUS;
}

#if defined(__SIZEOF_INT128__)
#define PVIA_MC_FIELD_HELPERS_AVAILABLE 1
static inline uint64_t pvia_mc_fp_add(uint64_t a, uint64_t b) {
    const uint64_t p = PVIA_MC_FIELD_MODULUS;
    const uint64_t sum = a + b;
    return sum >= p ? sum - p : sum;
}
static inline uint64_t pvia_mc_fp_sub(uint64_t a, uint64_t b) {
    const uint64_t p = PVIA_MC_FIELD_MODULUS;
    return a >= b ? a - b : p - (b - a);
}
static inline uint64_t pvia_mc_fp_mul(uint64_t a, uint64_t b) {
    const unsigned __int128 product =
        (unsigned __int128)a * (unsigned __int128)b;
    return (uint64_t)(product % PVIA_MC_FIELD_MODULUS);
}
static inline pvia_mc_field_element pvia_mc_field_mul(
    pvia_mc_field_element lhs,
    pvia_mc_field_element rhs) {
    pvia_mc_field_element out;
    const uint64_t ac = pvia_mc_fp_mul(lhs.real, rhs.real);
    const uint64_t bd =
        pvia_mc_fp_mul(lhs.imaginary, rhs.imaginary);
    const uint64_t ad =
        pvia_mc_fp_mul(lhs.real, rhs.imaginary);
    const uint64_t bc =
        pvia_mc_fp_mul(lhs.imaginary, rhs.real);
    out.real = pvia_mc_fp_sub(ac, bd);
    out.imaginary = pvia_mc_fp_add(ad, bc);
    return out;
}
#else
#define PVIA_MC_FIELD_HELPERS_AVAILABLE 0
#endif

#define PVIA_MC_STATEMENT_ABI_DOMAIN UINT64_C(0x50564d4353544142)
#define PVIA_MC_WITNESS_ABI_DOMAIN UINT64_C(0x50564d4357544142)
#define PVIA_MC_CAPABILITY_ABI_DOMAIN UINT64_C(0x50564d4343544142)
#define PVIA_MC_PROOF_COMMITMENT_DOMAIN UINT64_C(0x50564d554c505246)
#define PVIA_MC_CAPABILITY_BINDING_DOMAIN UINT64_C(0x50564d554c434150)
#define PVIA_MC_RELATION_BINDING_DOMAIN UINT64_C(0x50564d4352454c42)
#define PVIA_MC_RELATION_VERSION UINT64_C(1)
#define PVIA_MC_RELATION_DESCRIPTOR_WORDS ((size_t)25)

#define PVIA_MC_STATEMENT_BINDING_DOMAIN UINT64_C(0x50564d554c435354)

#define PVIA_MC_VSS_TRANSCRIPT_DOMAIN UINT64_C(0x505656535354524e)
#define PVIA_MC_VSS_DEALER_WITNESS_DOMAIN UINT64_C(0x5056565353445754)
#define PVIA_MC_VSS_LOCAL_WITNESS_DOMAIN UINT64_C(0x50565653534c5754)
#define PVIA_MC_VSS_WITNESS_VERSION UINT64_C(1)

#define PVIA_MC_LINEAR_BINDING_DOMAIN UINT64_C(0x50564c494e424e44)
#define PVIA_MC_LINEAR_WITNESS_DOMAIN UINT64_C(0x50564c494e57544e)

/* VSS dealer witness fixed header. Variable sections follow in this order:
 * transport bindings, row commitments, coefficient words.
 */
#define PVIA_MC_VSS_DEALER_FIXED_WORDS ((size_t)18)
#define PVIA_MC_VSS_DEALER_DOMAIN_INDEX ((size_t)0)
#define PVIA_MC_VSS_DEALER_VERSION_INDEX ((size_t)1)
#define PVIA_MC_VSS_DEALER_ID_INDEX ((size_t)2)
#define PVIA_MC_VSS_DEALER_WORLD_SIZE_INDEX ((size_t)3)
#define PVIA_MC_VSS_DEALER_THRESHOLD_INDEX ((size_t)4)
#define PVIA_MC_VSS_DEALER_ELEMENT_COUNT_INDEX ((size_t)5)
#define PVIA_MC_VSS_DEALER_AUTHENTICATED_INDEX ((size_t)6)
#define PVIA_MC_VSS_DEALER_TRANSPORT_COUNT_INDEX ((size_t)7)
#define PVIA_MC_VSS_DEALER_ROW_COUNT_INDEX ((size_t)8)
#define PVIA_MC_VSS_DEALER_COEFFICIENT_WORDS_INDEX ((size_t)9)
#define PVIA_MC_VSS_DEALER_CAPABILITY_BINDING_INDEX ((size_t)10)
#define PVIA_MC_VSS_DEALER_TRANSCRIPT_BINDING_INDEX ((size_t)14)

/* VSS local witness fixed header. Variable sections follow in this order:
 * transport bindings, row commitments, local row words.
 */
#define PVIA_MC_VSS_LOCAL_FIXED_WORDS ((size_t)23)
#define PVIA_MC_VSS_LOCAL_DOMAIN_INDEX ((size_t)0)
#define PVIA_MC_VSS_LOCAL_VERSION_INDEX ((size_t)1)
#define PVIA_MC_VSS_LOCAL_DEALER_INDEX ((size_t)2)
#define PVIA_MC_VSS_LOCAL_PARTICIPANT_INDEX ((size_t)3)
#define PVIA_MC_VSS_LOCAL_WORLD_SIZE_INDEX ((size_t)4)
#define PVIA_MC_VSS_LOCAL_THRESHOLD_INDEX ((size_t)5)
#define PVIA_MC_VSS_LOCAL_ELEMENT_COUNT_INDEX ((size_t)6)
#define PVIA_MC_VSS_LOCAL_AUTHENTICATED_INDEX ((size_t)7)
#define PVIA_MC_VSS_LOCAL_TRANSPORT_COUNT_INDEX ((size_t)8)
#define PVIA_MC_VSS_LOCAL_ROW_COUNT_INDEX ((size_t)9)
#define PVIA_MC_VSS_LOCAL_ROW_WORDS_INDEX ((size_t)10)
#define PVIA_MC_VSS_LOCAL_CAPABILITY_BINDING_INDEX ((size_t)11)
#define PVIA_MC_VSS_LOCAL_ROW_COMMITMENT_INDEX ((size_t)15)
#define PVIA_MC_VSS_LOCAL_TRANSCRIPT_BINDING_INDEX ((size_t)19)

/* Linear-combination witness fixed header. Each source then contains:
 * sharing_binding[4], coefficient_count, coefficient field pairs,
 * nested_vss_local_word_count, nested_vss_local_words.
 */
#define PVIA_MC_LINEAR_FIXED_WORDS ((size_t)8)
#define PVIA_MC_LINEAR_DOMAIN_INDEX ((size_t)0)
#define PVIA_MC_LINEAR_LOCAL_REAL_INDEX ((size_t)1)
#define PVIA_MC_LINEAR_LOCAL_IMAG_INDEX ((size_t)2)
#define PVIA_MC_LINEAR_SOURCE_COUNT_INDEX ((size_t)3)
#define PVIA_MC_LINEAR_BINDING_INDEX ((size_t)4)

/*
 * VSS transcript binding is BLAKE3-256 over:
 * [PVIA_MC_VSS_TRANSCRIPT_DOMAIN, dealer, world_size, threshold,
 *  element_count, authenticated, transport_binding_count,
 *  capability_binding[4] when authenticated,
 *  transport_bindings[4 * count], row_commitments[4 * world_size]].
 *
 * Linear binding is BLAKE3-256 over:
 * [PVIA_MC_LINEAR_BINDING_DOMAIN, source_count,
 *  for each source: sharing_binding[4], coefficient_count,
 *  coefficient field pairs].
 *
 * Statement binding is BLAKE3-256 over:
 * [PVIA_MC_STATEMENT_BINDING_DOMAIN, sid, checkpoint, multiplication_id,
 *  dealer, lhs_binding[4], rhs_binding[4], output_binding[4],
 *  context_binding[4]].
 */

/* Statement ABI: fixed 26 words. */
#define PVIA_MC_STATEMENT_WORDS ((size_t)26)
#define PVIA_MC_STMT_DOMAIN_INDEX ((size_t)0)
#define PVIA_MC_STMT_VERSION_INDEX ((size_t)1)
#define PVIA_MC_STMT_SID_INDEX ((size_t)2)
#define PVIA_MC_STMT_CHECKPOINT_INDEX ((size_t)3)
#define PVIA_MC_STMT_MULTIPLICATION_ID_INDEX ((size_t)4)
#define PVIA_MC_STMT_DEALER_INDEX ((size_t)5)
#define PVIA_MC_STMT_LHS_BINDING_INDEX ((size_t)6)
#define PVIA_MC_STMT_RHS_BINDING_INDEX ((size_t)10)
#define PVIA_MC_STMT_OUTPUT_BINDING_INDEX ((size_t)14)
#define PVIA_MC_STMT_CONTEXT_BINDING_INDEX ((size_t)18)
#define PVIA_MC_STMT_STATEMENT_BINDING_INDEX ((size_t)22)

/*
 * Witness ABI: 11-word header followed by three variable-length private
 * sharing-witness envelopes. Field elements occupy (real, imaginary) pairs.
 * lhs/rhs envelopes use VSS_LOCAL or LINEAR_COMBINATION; the output envelope
 * uses VSS_DEALER. Each envelope carries the sharing binding that must match
 * the corresponding statement binding.
 */
#define PVIA_MC_WITNESS_HEADER_WORDS ((size_t)11)
#define PVIA_MC_WITNESS_DOMAIN_INDEX ((size_t)0)
#define PVIA_MC_WITNESS_VERSION_INDEX ((size_t)1)
#define PVIA_MC_WITNESS_LHS_REAL_INDEX ((size_t)2)
#define PVIA_MC_WITNESS_LHS_IMAG_INDEX ((size_t)3)
#define PVIA_MC_WITNESS_RHS_REAL_INDEX ((size_t)4)
#define PVIA_MC_WITNESS_RHS_IMAG_INDEX ((size_t)5)
#define PVIA_MC_WITNESS_PRODUCT_REAL_INDEX ((size_t)6)
#define PVIA_MC_WITNESS_PRODUCT_IMAG_INDEX ((size_t)7)
#define PVIA_MC_WITNESS_LHS_SECTION_WORDS_INDEX ((size_t)8)
#define PVIA_MC_WITNESS_RHS_SECTION_WORDS_INDEX ((size_t)9)
#define PVIA_MC_WITNESS_OUTPUT_SECTION_WORDS_INDEX ((size_t)10)

/* Capability ABI v2: fixed 20 words. */
#define PVIA_MC_CAPABILITY_WORDS ((size_t)20)
#define PVIA_MC_CAP_DOMAIN_INDEX ((size_t)0)
#define PVIA_MC_CAP_VERSION_INDEX ((size_t)1)
#define PVIA_MC_CAP_AVAILABLE_INDEX ((size_t)2)
#define PVIA_MC_CAP_STRONG_SOUNDNESS_INDEX ((size_t)3)
#define PVIA_MC_CAP_ZERO_KNOWLEDGE_INDEX ((size_t)4)
#define PVIA_MC_CAP_BINDS_INPUT_INDEX ((size_t)5)
#define PVIA_MC_CAP_BINDS_OUTPUT_INDEX ((size_t)6)
#define PVIA_MC_CAP_PROTOCOL_ID_INDEX ((size_t)7)
#define PVIA_MC_CAP_RELATION_BINDING_INDEX ((size_t)8)
#define PVIA_MC_CAP_IMPLEMENTATION_BINDING_INDEX ((size_t)12)
#define PVIA_MC_CAP_CAPABILITY_BINDING_INDEX ((size_t)16)

/*
 * Canonical proof artifact returned by pvia_mc_provider_prove:
 *   [available, authenticated, zero_knowledge, proof_system_id,
 *    statement_binding[4], transcript_binding[4], proof_commitment[4],
 *    proof_word_count, proof_words...]
 *
 * proof_commitment = BLAKE3-256(words_le) where words are:
 *   [PVIA_MC_PROOF_COMMITMENT_DOMAIN,
 *    available, authenticated, zero_knowledge, proof_system_id,
 *    proof_word_count,
 *    statement_binding[4], transcript_binding[4], proof_words...]
 */
#define PVIA_MC_PROOF_HEADER_WORDS ((size_t)17)
#define PVIA_MC_PROOF_AVAILABLE_INDEX ((size_t)0)
#define PVIA_MC_PROOF_AUTHENTICATED_INDEX ((size_t)1)
#define PVIA_MC_PROOF_ZERO_KNOWLEDGE_INDEX ((size_t)2)
#define PVIA_MC_PROOF_SYSTEM_ID_INDEX ((size_t)3)
#define PVIA_MC_PROOF_STATEMENT_BINDING_INDEX ((size_t)4)
#define PVIA_MC_PROOF_TRANSCRIPT_BINDING_INDEX ((size_t)8)
#define PVIA_MC_PROOF_COMMITMENT_INDEX ((size_t)12)
#define PVIA_MC_PROOF_WORD_COUNT_INDEX ((size_t)16)

/* Stable envelope for each private sharing witness section. */
#define PVIA_MC_SHARING_WITNESS_DOMAIN UINT64_C(0x50564d4353574954)
#define PVIA_MC_SHARING_WITNESS_VERSION UINT64_C(1)
#define PVIA_MC_SHARING_KIND_VSS_LOCAL UINT64_C(1)
#define PVIA_MC_SHARING_KIND_LINEAR_COMBINATION UINT64_C(2)
#define PVIA_MC_SHARING_KIND_VSS_DEALER UINT64_C(3)
#define PVIA_MC_SHARING_WITNESS_HEADER_WORDS ((size_t)8)
#define PVIA_MC_SHARING_WITNESS_DOMAIN_INDEX ((size_t)0)
#define PVIA_MC_SHARING_WITNESS_VERSION_INDEX ((size_t)1)
#define PVIA_MC_SHARING_WITNESS_KIND_INDEX ((size_t)2)
#define PVIA_MC_SHARING_WITNESS_PAYLOAD_WORDS_INDEX ((size_t)3)
#define PVIA_MC_SHARING_WITNESS_BINDING_INDEX ((size_t)4)

/*
 * relation_binding = BLAKE3-256(words_le) for:
 *   [PVIA_MC_RELATION_BINDING_DOMAIN, PVIA_MC_RELATION_VERSION,
 *    PVIA_MC_ABI_VERSION, PVIA_MC_FIELD_MODULUS,
 *    PVIA_MC_FIELD_COMPONENT_WORDS,
 *    PVIA_MC_FIELD_EXTENSION_I_SQUARED_IS_NEG_ONE,
 *    PVIA_MC_STATEMENT_BINDING_DOMAIN, PVIA_MC_STATEMENT_ABI_DOMAIN,
 *    PVIA_MC_STATEMENT_WORDS, PVIA_MC_WITNESS_ABI_DOMAIN,
 *    PVIA_MC_WITNESS_HEADER_WORDS, PVIA_MC_SHARING_WITNESS_DOMAIN,
 *    PVIA_MC_SHARING_WITNESS_VERSION,
 *    PVIA_MC_SHARING_KIND_VSS_LOCAL,
 *    PVIA_MC_SHARING_KIND_LINEAR_COMBINATION,
 *    PVIA_MC_SHARING_KIND_VSS_DEALER,
 *    PVIA_MC_VSS_TRANSCRIPT_DOMAIN,
 *    PVIA_MC_VSS_DEALER_WITNESS_DOMAIN,
 *    PVIA_MC_VSS_LOCAL_WITNESS_DOMAIN, PVIA_MC_VSS_WITNESS_VERSION,
 *    PVIA_MC_VSS_DEALER_FIXED_WORDS, PVIA_MC_VSS_LOCAL_FIXED_WORDS,
 *    PVIA_MC_LINEAR_BINDING_DOMAIN, PVIA_MC_LINEAR_WITNESS_DOMAIN,
 *    PVIA_MC_LINEAR_FIXED_WORDS].
 *
 * capability_binding = BLAKE3-256(words_le) for:
 *   [PVIA_MC_CAPABILITY_BINDING_DOMAIN,
 *    available, strong_soundness, zero_knowledge,
 *    binds_input, binds_output, protocol_id,
 *    relation_binding[4], implementation_binding[4]]
 */

/* Required exported symbol names. */
#define PVIA_MC_ABI_VERSION_SYMBOL_NAME "pvia_mc_provider_abi_version"
#define PVIA_MC_ABI_CAPABILITIES_SYMBOL_NAME "pvia_mc_provider_capabilities"
#define PVIA_MC_ABI_PROVE_SYMBOL_NAME "pvia_mc_provider_prove"
#define PVIA_MC_ABI_VERIFY_SYMBOL_NAME "pvia_mc_provider_verify"

typedef uint32_t (*pvia_mc_provider_abi_version_fn)(void);
typedef int (*pvia_mc_provider_capabilities_fn)(
    uint64_t* output_words, size_t* inout_word_count);
typedef int (*pvia_mc_provider_prove_fn)(
    const uint64_t* statement_words, size_t statement_word_count,
    const uint64_t* witness_words, size_t witness_word_count,
    uint64_t* proof_words, size_t* inout_proof_word_count);
typedef int (*pvia_mc_provider_verify_fn)(
    const uint64_t* statement_words, size_t statement_word_count,
    const uint64_t* proof_words, size_t proof_word_count);

/* Provider libraries export these four functions with C linkage. */
uint32_t pvia_mc_provider_abi_version(void);
int pvia_mc_provider_capabilities(
    uint64_t* output_words, size_t* inout_word_count);
int pvia_mc_provider_prove(
    const uint64_t* statement_words, size_t statement_word_count,
    const uint64_t* witness_words, size_t witness_word_count,
    uint64_t* proof_words, size_t* inout_proof_word_count);
int pvia_mc_provider_verify(
    const uint64_t* statement_words, size_t statement_word_count,
    const uint64_t* proof_words, size_t proof_word_count);

#ifdef __cplusplus
}
#endif

#endif
