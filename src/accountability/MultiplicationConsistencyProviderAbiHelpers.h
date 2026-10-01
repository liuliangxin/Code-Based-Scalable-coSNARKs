#ifndef PVIA_MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_HELPERS_H
#define PVIA_MULTIPLICATION_CONSISTENCY_PROVIDER_ABI_HELPERS_H

#include "MultiplicationConsistencyProviderAbiC.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pvia_mc_word_span {
    const uint64_t* words;
    size_t word_count;
} pvia_mc_word_span;

typedef struct pvia_mc_statement_view {
    uint64_t sid;
    uint64_t checkpoint;
    uint64_t multiplication_id;
    uint64_t dealer;
    const uint64_t* lhs_sharing_binding;
    const uint64_t* rhs_sharing_binding;
    const uint64_t* output_sharing_binding;
    const uint64_t* context_binding;
    const uint64_t* statement_binding;
} pvia_mc_statement_view;

typedef struct pvia_mc_sharing_witness_view {
    uint64_t kind;
    const uint64_t* sharing_binding;
    pvia_mc_word_span payload;
} pvia_mc_sharing_witness_view;

typedef struct pvia_mc_witness_view {
    pvia_mc_field_element lhs_share;
    pvia_mc_field_element rhs_share;
    pvia_mc_field_element product_value;
    pvia_mc_word_span lhs_section;
    pvia_mc_word_span rhs_section;
    pvia_mc_word_span output_section;
} pvia_mc_witness_view;

typedef struct pvia_mc_vss_local_view {
    uint64_t dealer;
    uint64_t participant;
    uint64_t world_size;
    uint64_t threshold;
    uint64_t element_count;
    uint64_t authenticated;
    const uint64_t* capability_binding;
    const uint64_t* local_row_commitment;
    const uint64_t* transcript_binding;
    pvia_mc_word_span transport_binding_words;
    pvia_mc_word_span row_commitment_words;
    pvia_mc_word_span local_row_words;
} pvia_mc_vss_local_view;

typedef struct pvia_mc_vss_dealer_view {
    uint64_t dealer;
    uint64_t world_size;
    uint64_t threshold;
    uint64_t element_count;
    uint64_t authenticated;
    const uint64_t* capability_binding;
    const uint64_t* transcript_binding;
    pvia_mc_word_span transport_binding_words;
    pvia_mc_word_span row_commitment_words;
    pvia_mc_word_span coefficient_words;
} pvia_mc_vss_dealer_view;

typedef struct pvia_mc_linear_view {
    pvia_mc_field_element local_share;
    uint64_t source_count;
    const uint64_t* binding;
    pvia_mc_word_span source_words;
} pvia_mc_linear_view;

typedef struct pvia_mc_linear_source_view {
    const uint64_t* sharing_binding;
    uint64_t coefficient_count;
    pvia_mc_word_span coefficient_words;
    pvia_mc_word_span local_vss_words;
} pvia_mc_linear_source_view;

static inline int pvia_mc_size_add(
    size_t a, size_t b, size_t* out) {
    if (!out || b > (size_t)-1 - a) return 0;
    *out = a + b;
    return 1;
}

static inline int pvia_mc_size_mul(
    size_t a, size_t b, size_t* out) {
    if (!out || (a != 0 && b > (size_t)-1 / a)) return 0;
    *out = a * b;
    return 1;
}

static inline int pvia_mc_relation_descriptor_words(
    uint64_t* output_words, size_t* inout_word_count) {
    static const uint64_t descriptor[PVIA_MC_RELATION_DESCRIPTOR_WORDS] = {
        PVIA_MC_RELATION_BINDING_DOMAIN,
        PVIA_MC_RELATION_VERSION,
        (uint64_t)PVIA_MC_ABI_VERSION,
        PVIA_MC_FIELD_MODULUS,
        (uint64_t)PVIA_MC_FIELD_COMPONENT_WORDS,
        PVIA_MC_FIELD_EXTENSION_I_SQUARED_IS_NEG_ONE,
        PVIA_MC_STATEMENT_BINDING_DOMAIN,
        PVIA_MC_STATEMENT_ABI_DOMAIN,
        (uint64_t)PVIA_MC_STATEMENT_WORDS,
        PVIA_MC_WITNESS_ABI_DOMAIN,
        (uint64_t)PVIA_MC_WITNESS_HEADER_WORDS,
        PVIA_MC_SHARING_WITNESS_DOMAIN,
        PVIA_MC_SHARING_WITNESS_VERSION,
        PVIA_MC_SHARING_KIND_VSS_LOCAL,
        PVIA_MC_SHARING_KIND_LINEAR_COMBINATION,
        PVIA_MC_SHARING_KIND_VSS_DEALER,
        PVIA_MC_VSS_TRANSCRIPT_DOMAIN,
        PVIA_MC_VSS_DEALER_WITNESS_DOMAIN,
        PVIA_MC_VSS_LOCAL_WITNESS_DOMAIN,
        PVIA_MC_VSS_WITNESS_VERSION,
        (uint64_t)PVIA_MC_VSS_DEALER_FIXED_WORDS,
        (uint64_t)PVIA_MC_VSS_LOCAL_FIXED_WORDS,
        PVIA_MC_LINEAR_BINDING_DOMAIN,
        PVIA_MC_LINEAR_WITNESS_DOMAIN,
        (uint64_t)PVIA_MC_LINEAR_FIXED_WORDS};
    size_t i;
    if (!inout_word_count) return 0;
    if (!output_words) {
        *inout_word_count = PVIA_MC_RELATION_DESCRIPTOR_WORDS;
        return 1;
    }
    if (*inout_word_count < PVIA_MC_RELATION_DESCRIPTOR_WORDS) {
        *inout_word_count = PVIA_MC_RELATION_DESCRIPTOR_WORDS;
        return 0;
    }
    for (i = 0; i < PVIA_MC_RELATION_DESCRIPTOR_WORDS; ++i)
        output_words[i] = descriptor[i];
    *inout_word_count = PVIA_MC_RELATION_DESCRIPTOR_WORDS;
    return 1;
}

static inline int pvia_mc_digest_words_nonzero(
    const uint64_t* words) {
    size_t i;
    uint64_t any = 0;
    if (!words) return 0;
    for (i = 0; i < PVIA_MC_DIGEST_WORDS; ++i)
        any |= words[i];
    return any != 0;
}

static inline int pvia_mc_parse_statement(
    const uint64_t* words, size_t word_count,
    pvia_mc_statement_view* view) {
    if (!words || !view ||
        word_count != PVIA_MC_STATEMENT_WORDS ||
        words[PVIA_MC_STMT_DOMAIN_INDEX] !=
            PVIA_MC_STATEMENT_ABI_DOMAIN ||
        words[PVIA_MC_STMT_VERSION_INDEX] != PVIA_MC_ABI_VERSION ||
        words[PVIA_MC_STMT_SID_INDEX] == 0 ||
        words[PVIA_MC_STMT_CHECKPOINT_INDEX] == 0 ||
        words[PVIA_MC_STMT_MULTIPLICATION_ID_INDEX] == 0 ||
        words[PVIA_MC_STMT_DEALER_INDEX] > UINT32_MAX)
        return 0;
    view->sid = words[PVIA_MC_STMT_SID_INDEX];
    view->checkpoint = words[PVIA_MC_STMT_CHECKPOINT_INDEX];
    view->multiplication_id =
        words[PVIA_MC_STMT_MULTIPLICATION_ID_INDEX];
    view->dealer = words[PVIA_MC_STMT_DEALER_INDEX];
    view->lhs_sharing_binding =
        words + PVIA_MC_STMT_LHS_BINDING_INDEX;
    view->rhs_sharing_binding =
        words + PVIA_MC_STMT_RHS_BINDING_INDEX;
    view->output_sharing_binding =
        words + PVIA_MC_STMT_OUTPUT_BINDING_INDEX;
    view->context_binding =
        words + PVIA_MC_STMT_CONTEXT_BINDING_INDEX;
    view->statement_binding =
        words + PVIA_MC_STMT_STATEMENT_BINDING_INDEX;
    return pvia_mc_digest_words_nonzero(view->lhs_sharing_binding) &&
        pvia_mc_digest_words_nonzero(view->rhs_sharing_binding) &&
        pvia_mc_digest_words_nonzero(view->output_sharing_binding) &&
        pvia_mc_digest_words_nonzero(view->context_binding) &&
        pvia_mc_digest_words_nonzero(view->statement_binding);
}

static inline int pvia_mc_field_words_are_canonical(
    const uint64_t* words, size_t word_count) {
    size_t i;
    if (!words || (word_count & 1U) != 0) return 0;
    for (i = 0; i < word_count; ++i)
        if (words[i] >= PVIA_MC_FIELD_MODULUS) return 0;
    return 1;
}

static inline int pvia_mc_parse_sharing_witness(
    const uint64_t* words, size_t word_count,
    pvia_mc_sharing_witness_view* view) {
    if (!words || !view ||
        word_count < PVIA_MC_SHARING_WITNESS_HEADER_WORDS ||
        words[PVIA_MC_SHARING_WITNESS_DOMAIN_INDEX] !=
            PVIA_MC_SHARING_WITNESS_DOMAIN ||
        words[PVIA_MC_SHARING_WITNESS_VERSION_INDEX] !=
            PVIA_MC_SHARING_WITNESS_VERSION ||
        words[PVIA_MC_SHARING_WITNESS_KIND_INDEX] <
            PVIA_MC_SHARING_KIND_VSS_LOCAL ||
        words[PVIA_MC_SHARING_WITNESS_KIND_INDEX] >
            PVIA_MC_SHARING_KIND_VSS_DEALER ||
        words[PVIA_MC_SHARING_WITNESS_PAYLOAD_WORDS_INDEX] == 0 ||
        words[PVIA_MC_SHARING_WITNESS_PAYLOAD_WORDS_INDEX] !=
            word_count - PVIA_MC_SHARING_WITNESS_HEADER_WORDS)
        return 0;
    view->kind = words[PVIA_MC_SHARING_WITNESS_KIND_INDEX];
    view->sharing_binding =
        words + PVIA_MC_SHARING_WITNESS_BINDING_INDEX;
    view->payload.words =
        words + PVIA_MC_SHARING_WITNESS_HEADER_WORDS;
    view->payload.word_count =
        word_count - PVIA_MC_SHARING_WITNESS_HEADER_WORDS;
    return 1;
}

static inline int pvia_mc_parse_witness(
    const uint64_t* words, size_t word_count,
    pvia_mc_witness_view* view) {
    size_t lhs_n, rhs_n, out_n, total, offset;
    pvia_mc_sharing_witness_view envelope;
    if (!words || !view ||
        word_count < PVIA_MC_WITNESS_HEADER_WORDS ||
        words[PVIA_MC_WITNESS_DOMAIN_INDEX] !=
            PVIA_MC_WITNESS_ABI_DOMAIN ||
        words[PVIA_MC_WITNESS_VERSION_INDEX] != PVIA_MC_ABI_VERSION)
        return 0;

    view->lhs_share.real = words[PVIA_MC_WITNESS_LHS_REAL_INDEX];
    view->lhs_share.imaginary = words[PVIA_MC_WITNESS_LHS_IMAG_INDEX];
    view->rhs_share.real = words[PVIA_MC_WITNESS_RHS_REAL_INDEX];
    view->rhs_share.imaginary = words[PVIA_MC_WITNESS_RHS_IMAG_INDEX];
    view->product_value.real = words[PVIA_MC_WITNESS_PRODUCT_REAL_INDEX];
    view->product_value.imaginary =
        words[PVIA_MC_WITNESS_PRODUCT_IMAG_INDEX];
    if (!pvia_mc_field_is_canonical(view->lhs_share) ||
        !pvia_mc_field_is_canonical(view->rhs_share) ||
        !pvia_mc_field_is_canonical(view->product_value))
        return 0;

    lhs_n = (size_t)words[PVIA_MC_WITNESS_LHS_SECTION_WORDS_INDEX];
    rhs_n = (size_t)words[PVIA_MC_WITNESS_RHS_SECTION_WORDS_INDEX];
    out_n = (size_t)words[PVIA_MC_WITNESS_OUTPUT_SECTION_WORDS_INDEX];
    total = PVIA_MC_WITNESS_HEADER_WORDS;
    if (!pvia_mc_size_add(total, lhs_n, &total) ||
        !pvia_mc_size_add(total, rhs_n, &total) ||
        !pvia_mc_size_add(total, out_n, &total) ||
        total != word_count)
        return 0;

    offset = PVIA_MC_WITNESS_HEADER_WORDS;
    view->lhs_section.words = words + offset;
    view->lhs_section.word_count = lhs_n;
    offset += lhs_n;
    view->rhs_section.words = words + offset;
    view->rhs_section.word_count = rhs_n;
    offset += rhs_n;
    view->output_section.words = words + offset;
    view->output_section.word_count = out_n;

    if (!pvia_mc_parse_sharing_witness(
            view->lhs_section.words, view->lhs_section.word_count,
            &envelope) ||
        (envelope.kind != PVIA_MC_SHARING_KIND_VSS_LOCAL &&
         envelope.kind != PVIA_MC_SHARING_KIND_LINEAR_COMBINATION))
        return 0;
    if (!pvia_mc_parse_sharing_witness(
            view->rhs_section.words, view->rhs_section.word_count,
            &envelope) ||
        (envelope.kind != PVIA_MC_SHARING_KIND_VSS_LOCAL &&
         envelope.kind != PVIA_MC_SHARING_KIND_LINEAR_COMBINATION))
        return 0;
    if (!pvia_mc_parse_sharing_witness(
            view->output_section.words, view->output_section.word_count,
            &envelope) ||
        envelope.kind != PVIA_MC_SHARING_KIND_VSS_DEALER)
        return 0;
    return 1;
}

static inline int pvia_mc_parse_vss_local(
    const uint64_t* words, size_t word_count,
    pvia_mc_vss_local_view* view) {
    size_t transport_n, row_n, row_word_n, expected, tmp;
    if (!words || !view ||
        word_count < PVIA_MC_VSS_LOCAL_FIXED_WORDS ||
        words[PVIA_MC_VSS_LOCAL_DOMAIN_INDEX] !=
            PVIA_MC_VSS_LOCAL_WITNESS_DOMAIN ||
        words[PVIA_MC_VSS_LOCAL_VERSION_INDEX] !=
            PVIA_MC_VSS_WITNESS_VERSION ||
        words[PVIA_MC_VSS_LOCAL_AUTHENTICATED_INDEX] > 1)
        return 0;
    transport_n =
        (size_t)words[PVIA_MC_VSS_LOCAL_TRANSPORT_COUNT_INDEX];
    row_n = (size_t)words[PVIA_MC_VSS_LOCAL_ROW_COUNT_INDEX];
    row_word_n = (size_t)words[PVIA_MC_VSS_LOCAL_ROW_WORDS_INDEX];
    if (row_n !=
        (size_t)words[PVIA_MC_VSS_LOCAL_WORLD_SIZE_INDEX])
        return 0;

    expected = PVIA_MC_VSS_LOCAL_FIXED_WORDS;
    if (!pvia_mc_size_mul(transport_n, PVIA_MC_DIGEST_WORDS, &tmp) ||
        !pvia_mc_size_add(expected, tmp, &expected) ||
        !pvia_mc_size_mul(row_n, PVIA_MC_DIGEST_WORDS, &tmp) ||
        !pvia_mc_size_add(expected, tmp, &expected) ||
        !pvia_mc_size_add(expected, row_word_n, &expected) ||
        expected != word_count)
        return 0;

    view->dealer = words[PVIA_MC_VSS_LOCAL_DEALER_INDEX];
    view->participant = words[PVIA_MC_VSS_LOCAL_PARTICIPANT_INDEX];
    view->world_size = words[PVIA_MC_VSS_LOCAL_WORLD_SIZE_INDEX];
    view->threshold = words[PVIA_MC_VSS_LOCAL_THRESHOLD_INDEX];
    view->element_count = words[PVIA_MC_VSS_LOCAL_ELEMENT_COUNT_INDEX];
    view->authenticated = words[PVIA_MC_VSS_LOCAL_AUTHENTICATED_INDEX];
    if (view->world_size < 2 ||
        view->dealer >= view->world_size ||
        view->participant >= view->world_size ||
        view->threshold >= view->world_size ||
        view->element_count == 0)
        return 0;
    view->capability_binding =
        words + PVIA_MC_VSS_LOCAL_CAPABILITY_BINDING_INDEX;
    view->local_row_commitment =
        words + PVIA_MC_VSS_LOCAL_ROW_COMMITMENT_INDEX;
    view->transcript_binding =
        words + PVIA_MC_VSS_LOCAL_TRANSCRIPT_BINDING_INDEX;

    expected = PVIA_MC_VSS_LOCAL_FIXED_WORDS;
    view->transport_binding_words.words = words + expected;
    view->transport_binding_words.word_count =
        transport_n * PVIA_MC_DIGEST_WORDS;
    expected += view->transport_binding_words.word_count;
    view->row_commitment_words.words = words + expected;
    view->row_commitment_words.word_count =
        row_n * PVIA_MC_DIGEST_WORDS;
    expected += view->row_commitment_words.word_count;
    view->local_row_words.words = words + expected;
    view->local_row_words.word_count = row_word_n;
    return pvia_mc_field_words_are_canonical(
        view->local_row_words.words, view->local_row_words.word_count);
}

static inline int pvia_mc_parse_vss_dealer(
    const uint64_t* words, size_t word_count,
    pvia_mc_vss_dealer_view* view) {
    size_t transport_n, row_n, coeff_n, expected, tmp;
    if (!words || !view ||
        word_count < PVIA_MC_VSS_DEALER_FIXED_WORDS ||
        words[PVIA_MC_VSS_DEALER_DOMAIN_INDEX] !=
            PVIA_MC_VSS_DEALER_WITNESS_DOMAIN ||
        words[PVIA_MC_VSS_DEALER_VERSION_INDEX] !=
            PVIA_MC_VSS_WITNESS_VERSION ||
        words[PVIA_MC_VSS_DEALER_AUTHENTICATED_INDEX] > 1)
        return 0;
    transport_n =
        (size_t)words[PVIA_MC_VSS_DEALER_TRANSPORT_COUNT_INDEX];
    row_n = (size_t)words[PVIA_MC_VSS_DEALER_ROW_COUNT_INDEX];
    coeff_n =
        (size_t)words[PVIA_MC_VSS_DEALER_COEFFICIENT_WORDS_INDEX];
    if (row_n !=
        (size_t)words[PVIA_MC_VSS_DEALER_WORLD_SIZE_INDEX])
        return 0;

    expected = PVIA_MC_VSS_DEALER_FIXED_WORDS;
    if (!pvia_mc_size_mul(transport_n, PVIA_MC_DIGEST_WORDS, &tmp) ||
        !pvia_mc_size_add(expected, tmp, &expected) ||
        !pvia_mc_size_mul(row_n, PVIA_MC_DIGEST_WORDS, &tmp) ||
        !pvia_mc_size_add(expected, tmp, &expected) ||
        !pvia_mc_size_add(expected, coeff_n, &expected) ||
        expected != word_count)
        return 0;

    view->dealer = words[PVIA_MC_VSS_DEALER_ID_INDEX];
    view->world_size = words[PVIA_MC_VSS_DEALER_WORLD_SIZE_INDEX];
    view->threshold = words[PVIA_MC_VSS_DEALER_THRESHOLD_INDEX];
    view->element_count = words[PVIA_MC_VSS_DEALER_ELEMENT_COUNT_INDEX];
    view->authenticated =
        words[PVIA_MC_VSS_DEALER_AUTHENTICATED_INDEX];
    if (view->world_size < 2 ||
        view->dealer >= view->world_size ||
        view->threshold >= view->world_size ||
        view->element_count == 0)
        return 0;
    view->capability_binding =
        words + PVIA_MC_VSS_DEALER_CAPABILITY_BINDING_INDEX;
    view->transcript_binding =
        words + PVIA_MC_VSS_DEALER_TRANSCRIPT_BINDING_INDEX;

    expected = PVIA_MC_VSS_DEALER_FIXED_WORDS;
    view->transport_binding_words.words = words + expected;
    view->transport_binding_words.word_count =
        transport_n * PVIA_MC_DIGEST_WORDS;
    expected += view->transport_binding_words.word_count;
    view->row_commitment_words.words = words + expected;
    view->row_commitment_words.word_count =
        row_n * PVIA_MC_DIGEST_WORDS;
    expected += view->row_commitment_words.word_count;
    view->coefficient_words.words = words + expected;
    view->coefficient_words.word_count = coeff_n;
    return pvia_mc_field_words_are_canonical(
        view->coefficient_words.words, view->coefficient_words.word_count);
}

static inline int pvia_mc_parse_linear(
    const uint64_t* words, size_t word_count,
    pvia_mc_linear_view* view) {
    if (!words || !view ||
        word_count < PVIA_MC_LINEAR_FIXED_WORDS ||
        words[PVIA_MC_LINEAR_DOMAIN_INDEX] !=
            PVIA_MC_LINEAR_WITNESS_DOMAIN ||
        words[PVIA_MC_LINEAR_SOURCE_COUNT_INDEX] == 0)
        return 0;
    view->local_share.real = words[PVIA_MC_LINEAR_LOCAL_REAL_INDEX];
    view->local_share.imaginary = words[PVIA_MC_LINEAR_LOCAL_IMAG_INDEX];
    if (!pvia_mc_field_is_canonical(view->local_share))
        return 0;
    view->source_count = words[PVIA_MC_LINEAR_SOURCE_COUNT_INDEX];
    view->binding = words + PVIA_MC_LINEAR_BINDING_INDEX;
    view->source_words.words = words + PVIA_MC_LINEAR_FIXED_WORDS;
    view->source_words.word_count =
        word_count - PVIA_MC_LINEAR_FIXED_WORDS;
    return 1;
}

static inline int pvia_mc_linear_source_next(
    const pvia_mc_linear_view* linear,
    size_t* offset,
    pvia_mc_linear_source_view* source) {
    const uint64_t* words;
    size_t remaining, coefficient_n, coefficient_words_n, local_n, pos;
    pvia_mc_vss_local_view local_view;
    if (!linear || !offset || !source ||
        *offset > linear->source_words.word_count)
        return 0;
    words = linear->source_words.words + *offset;
    remaining = linear->source_words.word_count - *offset;
    if (remaining < 5) return 0;
    source->sharing_binding = words;
    coefficient_n = (size_t)words[4];
    if (coefficient_n == 0 ||
        !pvia_mc_size_mul(coefficient_n, 2, &coefficient_words_n) ||
        coefficient_words_n > remaining - 5)
        return 0;
    source->coefficient_count = (uint64_t)coefficient_n;
    source->coefficient_words.words = words + 5;
    source->coefficient_words.word_count = coefficient_words_n;
    if (!pvia_mc_field_words_are_canonical(
            source->coefficient_words.words,
            source->coefficient_words.word_count))
        return 0;
    pos = 5 + coefficient_words_n;
    if (pos >= remaining) return 0;
    local_n = (size_t)words[pos++];
    if (local_n == 0 || local_n > remaining - pos)
        return 0;
    source->local_vss_words.words = words + pos;
    source->local_vss_words.word_count = local_n;
    if (!pvia_mc_parse_vss_local(
            source->local_vss_words.words,
            source->local_vss_words.word_count,
            &local_view))
        return 0;
    *offset += pos + local_n;
    return 1;
}


static inline int pvia_mc_validate_sharing_payload(
    const uint64_t* words, size_t word_count) {
    pvia_mc_sharing_witness_view envelope;
    if (!pvia_mc_parse_sharing_witness(words, word_count, &envelope))
        return 0;
    if (envelope.kind == PVIA_MC_SHARING_KIND_VSS_LOCAL) {
        pvia_mc_vss_local_view local;
        return pvia_mc_parse_vss_local(
            envelope.payload.words, envelope.payload.word_count, &local);
    }
    if (envelope.kind == PVIA_MC_SHARING_KIND_VSS_DEALER) {
        pvia_mc_vss_dealer_view dealer;
        return pvia_mc_parse_vss_dealer(
            envelope.payload.words, envelope.payload.word_count, &dealer);
    }
    if (envelope.kind == PVIA_MC_SHARING_KIND_LINEAR_COMBINATION) {
        pvia_mc_linear_view linear;
        size_t offset = 0;
        uint64_t i;
        if (!pvia_mc_parse_linear(
                envelope.payload.words, envelope.payload.word_count,
                &linear))
            return 0;
        for (i = 0; i < linear.source_count; ++i) {
            pvia_mc_linear_source_view source;
            if (!pvia_mc_linear_source_next(
                    &linear, &offset, &source))
                return 0;
        }
        return offset == linear.source_words.word_count;
    }
    return 0;
}

static inline int pvia_mc_validate_witness_payloads(
    const pvia_mc_witness_view* witness) {
    if (!witness) return 0;
    return pvia_mc_validate_sharing_payload(
               witness->lhs_section.words,
               witness->lhs_section.word_count) &&
        pvia_mc_validate_sharing_payload(
               witness->rhs_section.words,
               witness->rhs_section.word_count) &&
        pvia_mc_validate_sharing_payload(
               witness->output_section.words,
               witness->output_section.word_count);
}

#ifdef __cplusplus
}
#endif

#endif
