#ifndef PVIA_MULTIPLICATION_CONSISTENCY_PROVIDER_RELATION_REFERENCE_H
#define PVIA_MULTIPLICATION_CONSISTENCY_PROVIDER_RELATION_REFERENCE_H

#include "MultiplicationConsistencyProviderAbiHelpers.h"
#include "blake3.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline void pvia_mc_reference_hash_words(
    const uint64_t* words, size_t word_count,
    uint64_t out[PVIA_MC_DIGEST_WORDS]) {
    blake3_hasher hasher;
    unsigned char digest[BLAKE3_OUT_LEN];
    blake3_hasher_init(&hasher);
    if (words && word_count != 0) {
        blake3_hasher_update(
            &hasher, words, word_count * sizeof(uint64_t));
    }
    blake3_hasher_finalize(&hasher, digest, sizeof(digest));
    memcpy(out, digest, PVIA_MC_DIGEST_WORDS * sizeof(uint64_t));
}

static inline int pvia_mc_reference_digest_equal(
    const uint64_t* lhs, const uint64_t* rhs) {
    size_t i;
    uint64_t diff = 0;
    if (!lhs || !rhs) return 0;
    for (i = 0; i < PVIA_MC_DIGEST_WORDS; ++i)
        diff |= lhs[i] ^ rhs[i];
    return diff == 0;
}


static inline int pvia_mc_reference_relation_binding(
    uint64_t out[PVIA_MC_DIGEST_WORDS]) {
    uint64_t descriptor[PVIA_MC_RELATION_DESCRIPTOR_WORDS];
    size_t count = PVIA_MC_RELATION_DESCRIPTOR_WORDS;
    if (!out ||
        !pvia_mc_relation_descriptor_words(descriptor, &count) ||
        count != PVIA_MC_RELATION_DESCRIPTOR_WORDS)
        return 0;
    pvia_mc_reference_hash_words(descriptor, count, out);
    return pvia_mc_digest_words_nonzero(out);
}

static inline int pvia_mc_reference_capability_binding(
    uint64_t available, uint64_t strong_soundness,
    uint64_t zero_knowledge, uint64_t binds_input,
    uint64_t binds_output, uint64_t protocol_id,
    const uint64_t relation_binding[PVIA_MC_DIGEST_WORDS],
    const uint64_t implementation_binding[PVIA_MC_DIGEST_WORDS],
    uint64_t out[PVIA_MC_DIGEST_WORDS]) {
    uint64_t words[7 + 2 * PVIA_MC_DIGEST_WORDS];
    size_t pos = 0, i;
    if (!out || available > 1 || strong_soundness > 1 ||
        zero_knowledge > 1 || binds_input > 1 || binds_output > 1 ||
        protocol_id == 0 ||
        !pvia_mc_digest_words_nonzero(relation_binding) ||
        !pvia_mc_digest_words_nonzero(implementation_binding))
        return 0;
    words[pos++] = PVIA_MC_CAPABILITY_BINDING_DOMAIN;
    words[pos++] = available;
    words[pos++] = strong_soundness;
    words[pos++] = zero_knowledge;
    words[pos++] = binds_input;
    words[pos++] = binds_output;
    words[pos++] = protocol_id;
    for (i = 0; i < PVIA_MC_DIGEST_WORDS; ++i)
        words[pos++] = relation_binding[i];
    for (i = 0; i < PVIA_MC_DIGEST_WORDS; ++i)
        words[pos++] = implementation_binding[i];
    pvia_mc_reference_hash_words(words, pos, out);
    return pvia_mc_digest_words_nonzero(out);
}

static inline int pvia_mc_reference_write_capabilities(
    uint64_t protocol_id,
    const uint64_t implementation_binding[PVIA_MC_DIGEST_WORDS],
    uint64_t* output_words, size_t* inout_word_count) {
    uint64_t relation_binding[PVIA_MC_DIGEST_WORDS];
    uint64_t capability_binding[PVIA_MC_DIGEST_WORDS];
    size_t i;
    if (!inout_word_count) return 0;
    if (!output_words) {
        *inout_word_count = PVIA_MC_CAPABILITY_WORDS;
        return 1;
    }
    if (*inout_word_count < PVIA_MC_CAPABILITY_WORDS) {
        *inout_word_count = PVIA_MC_CAPABILITY_WORDS;
        return 0;
    }
    if (!pvia_mc_reference_relation_binding(relation_binding) ||
        !pvia_mc_reference_capability_binding(
            1, 1, 1, 1, 1, protocol_id,
            relation_binding, implementation_binding,
            capability_binding))
        return 0;
    memset(
        output_words, 0,
        PVIA_MC_CAPABILITY_WORDS * sizeof(uint64_t));
    output_words[PVIA_MC_CAP_DOMAIN_INDEX] =
        PVIA_MC_CAPABILITY_ABI_DOMAIN;
    output_words[PVIA_MC_CAP_VERSION_INDEX] =
        PVIA_MC_ABI_VERSION;
    output_words[PVIA_MC_CAP_AVAILABLE_INDEX] = 1;
    output_words[PVIA_MC_CAP_STRONG_SOUNDNESS_INDEX] = 1;
    output_words[PVIA_MC_CAP_ZERO_KNOWLEDGE_INDEX] = 1;
    output_words[PVIA_MC_CAP_BINDS_INPUT_INDEX] = 1;
    output_words[PVIA_MC_CAP_BINDS_OUTPUT_INDEX] = 1;
    output_words[PVIA_MC_CAP_PROTOCOL_ID_INDEX] = protocol_id;
    for (i = 0; i < PVIA_MC_DIGEST_WORDS; ++i) {
        output_words[PVIA_MC_CAP_RELATION_BINDING_INDEX + i] =
            relation_binding[i];
        output_words[PVIA_MC_CAP_IMPLEMENTATION_BINDING_INDEX + i] =
            implementation_binding[i];
        output_words[PVIA_MC_CAP_CAPABILITY_BINDING_INDEX + i] =
            capability_binding[i];
    }
    *inout_word_count = PVIA_MC_CAPABILITY_WORDS;
    return 1;
}


static inline int pvia_mc_reference_proof_commitment(
    uint32_t proof_system_id,
    const uint64_t statement_binding[PVIA_MC_DIGEST_WORDS],
    const uint64_t transcript_binding[PVIA_MC_DIGEST_WORDS],
    const uint64_t* proof_words, size_t proof_word_count,
    uint64_t out[PVIA_MC_DIGEST_WORDS]) {
    blake3_hasher hasher;
    unsigned char digest[BLAKE3_OUT_LEN];
    uint64_t fixed[6];
    if (!out || proof_system_id == 0 || proof_word_count == 0 ||
        !proof_words ||
        !pvia_mc_digest_words_nonzero(statement_binding) ||
        !pvia_mc_digest_words_nonzero(transcript_binding))
        return 0;
    fixed[0] = PVIA_MC_PROOF_COMMITMENT_DOMAIN;
    fixed[1] = 1;
    fixed[2] = 1;
    fixed[3] = 1;
    fixed[4] = (uint64_t)proof_system_id;
    fixed[5] = (uint64_t)proof_word_count;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, fixed, sizeof(fixed));
    blake3_hasher_update(
        &hasher, statement_binding,
        PVIA_MC_DIGEST_WORDS * sizeof(uint64_t));
    blake3_hasher_update(
        &hasher, transcript_binding,
        PVIA_MC_DIGEST_WORDS * sizeof(uint64_t));
    blake3_hasher_update(
        &hasher, proof_words,
        proof_word_count * sizeof(uint64_t));
    blake3_hasher_finalize(&hasher, digest, sizeof(digest));
    memcpy(out, digest, PVIA_MC_DIGEST_WORDS * sizeof(uint64_t));
    return pvia_mc_digest_words_nonzero(out);
}

static inline int pvia_mc_reference_write_proof_artifact(
    uint32_t proof_system_id,
    const uint64_t statement_binding[PVIA_MC_DIGEST_WORDS],
    const uint64_t transcript_binding[PVIA_MC_DIGEST_WORDS],
    const uint64_t* provider_proof_words,
    size_t provider_proof_word_count,
    uint64_t* output_words, size_t* inout_word_count) {
    uint64_t commitment[PVIA_MC_DIGEST_WORDS];
    size_t required, i;
    if (!inout_word_count ||
        provider_proof_word_count == 0 ||
        provider_proof_word_count >
            (size_t)-1 - PVIA_MC_PROOF_HEADER_WORDS)
        return 0;
    required =
        PVIA_MC_PROOF_HEADER_WORDS + provider_proof_word_count;
    if (!output_words) {
        *inout_word_count = required;
        return 1;
    }
    if (*inout_word_count < required) {
        *inout_word_count = required;
        return 0;
    }
    if (!pvia_mc_reference_proof_commitment(
            proof_system_id, statement_binding,
            transcript_binding, provider_proof_words,
            provider_proof_word_count, commitment))
        return 0;

    output_words[PVIA_MC_PROOF_AVAILABLE_INDEX] = 1;
    output_words[PVIA_MC_PROOF_AUTHENTICATED_INDEX] = 1;
    output_words[PVIA_MC_PROOF_ZERO_KNOWLEDGE_INDEX] = 1;
    output_words[PVIA_MC_PROOF_SYSTEM_ID_INDEX] =
        (uint64_t)proof_system_id;
    for (i = 0; i < PVIA_MC_DIGEST_WORDS; ++i) {
        output_words[
            PVIA_MC_PROOF_STATEMENT_BINDING_INDEX + i] =
            statement_binding[i];
        output_words[
            PVIA_MC_PROOF_TRANSCRIPT_BINDING_INDEX + i] =
            transcript_binding[i];
        output_words[
            PVIA_MC_PROOF_COMMITMENT_INDEX + i] =
            commitment[i];
    }
    output_words[PVIA_MC_PROOF_WORD_COUNT_INDEX] =
        (uint64_t)provider_proof_word_count;
    memcpy(
        output_words + PVIA_MC_PROOF_HEADER_WORDS,
        provider_proof_words,
        provider_proof_word_count * sizeof(uint64_t));
    *inout_word_count = required;
    return 1;
}

static inline int pvia_mc_reference_digest_vector_nonzero(
    const uint64_t* words, size_t digest_count) {
    size_t i;
    if (digest_count != 0 && !words) return 0;
    for (i = 0; i < digest_count; ++i) {
        if (!pvia_mc_digest_words_nonzero(
                words + i * PVIA_MC_DIGEST_WORDS))
            return 0;
    }
    return 1;
}

static inline pvia_mc_field_element pvia_mc_reference_field_add(
    pvia_mc_field_element lhs, pvia_mc_field_element rhs) {
    pvia_mc_field_element out;
    out.real = pvia_mc_fp_add(lhs.real, rhs.real);
    out.imaginary = pvia_mc_fp_add(lhs.imaginary, rhs.imaginary);
    return out;
}

static inline int pvia_mc_reference_field_equal(
    pvia_mc_field_element lhs, pvia_mc_field_element rhs) {
    return lhs.real == rhs.real && lhs.imaginary == rhs.imaginary;
}

static inline int pvia_mc_reference_vss_transcript_binding(
    uint64_t dealer, uint64_t world_size, uint64_t threshold,
    uint64_t element_count, uint64_t authenticated,
    const uint64_t* capability_binding,
    const uint64_t* transport_binding_words,
    size_t transport_binding_count,
    const uint64_t* row_commitment_words,
    size_t row_commitment_count,
    uint64_t out[PVIA_MC_DIGEST_WORDS]) {
    blake3_hasher hasher;
    unsigned char digest[BLAKE3_OUT_LEN];
    uint64_t fixed[7];
    if (!out || world_size < 2 || dealer >= world_size ||
        threshold >= world_size || element_count == 0 ||
        authenticated > 1 ||
        row_commitment_count != (size_t)world_size ||
        !pvia_mc_reference_digest_vector_nonzero(
            row_commitment_words, row_commitment_count))
        return 0;
    if (authenticated) {
        if (!pvia_mc_digest_words_nonzero(capability_binding) ||
            transport_binding_count == 0 ||
            !pvia_mc_reference_digest_vector_nonzero(
                transport_binding_words, transport_binding_count))
            return 0;
    } else {
        if ((capability_binding &&
             pvia_mc_digest_words_nonzero(capability_binding)) ||
            transport_binding_count != 0)
            return 0;
    }

    fixed[0] = PVIA_MC_VSS_TRANSCRIPT_DOMAIN;
    fixed[1] = dealer;
    fixed[2] = world_size;
    fixed[3] = threshold;
    fixed[4] = element_count;
    fixed[5] = authenticated;
    fixed[6] = (uint64_t)transport_binding_count;

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, fixed, sizeof(fixed));
    if (authenticated) {
        blake3_hasher_update(
            &hasher, capability_binding,
            PVIA_MC_DIGEST_WORDS * sizeof(uint64_t));
        blake3_hasher_update(
            &hasher, transport_binding_words,
            transport_binding_count *
                PVIA_MC_DIGEST_WORDS * sizeof(uint64_t));
    }
    blake3_hasher_update(
        &hasher, row_commitment_words,
        row_commitment_count *
            PVIA_MC_DIGEST_WORDS * sizeof(uint64_t));
    blake3_hasher_finalize(&hasher, digest, sizeof(digest));
    memcpy(out, digest, PVIA_MC_DIGEST_WORDS * sizeof(uint64_t));
    return 1;
}

static inline int pvia_mc_reference_validate_vss_local(
    const pvia_mc_vss_local_view* view) {
    size_t dimension, expected_field_count, expected_word_count;
    uint64_t local_commitment[PVIA_MC_DIGEST_WORDS];
    uint64_t transcript[PVIA_MC_DIGEST_WORDS];
    const uint64_t* participant_commitment;
    size_t transport_count, row_count;
    if (!view || view->world_size < 2 ||
        view->dealer >= view->world_size ||
        view->participant >= view->world_size ||
        view->threshold >= view->world_size ||
        view->element_count == 0)
        return 0;

    dimension = (size_t)view->threshold + 1;
    if (!pvia_mc_size_mul(
            (size_t)view->element_count, dimension,
            &expected_field_count) ||
        !pvia_mc_size_mul(
            expected_field_count, 2, &expected_word_count) ||
        view->local_row_words.word_count != expected_word_count ||
        !pvia_mc_field_words_are_canonical(
            view->local_row_words.words,
            view->local_row_words.word_count))
        return 0;

    pvia_mc_reference_hash_words(
        view->local_row_words.words,
        view->local_row_words.word_count,
        local_commitment);
    if (!pvia_mc_reference_digest_equal(
            local_commitment, view->local_row_commitment))
        return 0;

    row_count =
        view->row_commitment_words.word_count / PVIA_MC_DIGEST_WORDS;
    if (row_count != (size_t)view->world_size)
        return 0;
    participant_commitment =
        view->row_commitment_words.words +
        (size_t)view->participant * PVIA_MC_DIGEST_WORDS;
    if (!pvia_mc_reference_digest_equal(
            participant_commitment, view->local_row_commitment))
        return 0;

    transport_count =
        view->transport_binding_words.word_count /
        PVIA_MC_DIGEST_WORDS;
    if (!pvia_mc_reference_vss_transcript_binding(
            view->dealer, view->world_size, view->threshold,
            view->element_count, view->authenticated,
            view->capability_binding,
            view->transport_binding_words.words, transport_count,
            view->row_commitment_words.words, row_count,
            transcript))
        return 0;
    return pvia_mc_reference_digest_equal(
        transcript, view->transcript_binding);
}

static inline int pvia_mc_reference_validate_vss_dealer(
    const pvia_mc_vss_dealer_view* view) {
    size_t dimension, matrix_fields, coefficient_word_count;
    size_t fields_per_rank, row_word_count;
    size_t participant, k, a, b;
    uint64_t transcript[PVIA_MC_DIGEST_WORDS];
    uint64_t row_digest[PVIA_MC_DIGEST_WORDS];
    uint64_t* row_words = NULL;
    size_t transport_count, row_count;
    if (!view || view->world_size < 2 ||
        view->dealer >= view->world_size ||
        view->threshold >= view->world_size ||
        view->element_count == 0)
        return 0;
    dimension = (size_t)view->threshold + 1;
    if (!pvia_mc_size_mul(
            (size_t)view->element_count, dimension, &matrix_fields) ||
        !pvia_mc_size_mul(matrix_fields, dimension, &matrix_fields) ||
        !pvia_mc_size_mul(matrix_fields, 2, &coefficient_word_count) ||
        view->coefficient_words.word_count != coefficient_word_count ||
        !pvia_mc_field_words_are_canonical(
            view->coefficient_words.words,
            view->coefficient_words.word_count))
        return 0;

    for (k = 0; k < (size_t)view->element_count; ++k) {
        for (a = 0; a < dimension; ++a) {
            for (b = 0; b < dimension; ++b) {
                size_t lhs_field =
                    (k * dimension + a) * dimension + b;
                size_t rhs_field =
                    (k * dimension + b) * dimension + a;
                pvia_mc_field_element lhs = {
                    view->coefficient_words.words[2 * lhs_field],
                    view->coefficient_words.words[2 * lhs_field + 1]};
                pvia_mc_field_element rhs = {
                    view->coefficient_words.words[2 * rhs_field],
                    view->coefficient_words.words[2 * rhs_field + 1]};
                if (!pvia_mc_reference_field_equal(lhs, rhs))
                    return 0;
            }
        }
    }

    if (!pvia_mc_size_mul(
            (size_t)view->element_count, dimension, &fields_per_rank) ||
        !pvia_mc_size_mul(fields_per_rank, 2, &row_word_count))
        return 0;
    row_words = (uint64_t*)calloc(
        row_word_count ? row_word_count : 1, sizeof(uint64_t));
    if (!row_words) return 0;

    row_count =
        view->row_commitment_words.word_count / PVIA_MC_DIGEST_WORDS;
    if (row_count != (size_t)view->world_size) {
        free(row_words);
        return 0;
    }
    for (participant = 0;
         participant < (size_t)view->world_size; ++participant) {
        pvia_mc_field_element x = {
            (uint64_t)(participant + 1), 0};
        memset(row_words, 0, row_word_count * sizeof(uint64_t));
        for (k = 0; k < (size_t)view->element_count; ++k) {
            for (b = 0; b < dimension; ++b) {
                pvia_mc_field_element value = {0, 0};
                pvia_mc_field_element power = {1, 0};
                for (a = 0; a < dimension; ++a) {
                    size_t field_index =
                        (k * dimension + a) * dimension + b;
                    pvia_mc_field_element coefficient = {
                        view->coefficient_words.words[
                            2 * field_index],
                        view->coefficient_words.words[
                            2 * field_index + 1]};
                    value = pvia_mc_reference_field_add(
                        value,
                        pvia_mc_field_mul(coefficient, power));
                    power = pvia_mc_field_mul(power, x);
                }
                row_words[2 * (k * dimension + b)] = value.real;
                row_words[2 * (k * dimension + b) + 1] =
                    value.imaginary;
            }
        }
        pvia_mc_reference_hash_words(
            row_words, row_word_count, row_digest);
        if (!pvia_mc_reference_digest_equal(
                row_digest,
                view->row_commitment_words.words +
                    participant * PVIA_MC_DIGEST_WORDS)) {
            free(row_words);
            return 0;
        }
    }
    free(row_words);

    transport_count =
        view->transport_binding_words.word_count /
        PVIA_MC_DIGEST_WORDS;
    if (!pvia_mc_reference_vss_transcript_binding(
            view->dealer, view->world_size, view->threshold,
            view->element_count, view->authenticated,
            view->capability_binding,
            view->transport_binding_words.words, transport_count,
            view->row_commitment_words.words, row_count,
            transcript))
        return 0;
    return pvia_mc_reference_digest_equal(
        transcript, view->transcript_binding);
}

static inline int pvia_mc_reference_validate_linear(
    const pvia_mc_linear_view* linear,
    uint64_t expected_participant,
    pvia_mc_field_element* local_share_out) {
    blake3_hasher hasher;
    unsigned char digest[BLAKE3_OUT_LEN];
    uint64_t fixed[2];
    uint64_t binding[PVIA_MC_DIGEST_WORDS];
    pvia_mc_field_element total = {0, 0};
    size_t offset = 0;
    uint64_t i;
    if (!linear || linear->source_count == 0 ||
        !pvia_mc_digest_words_nonzero(linear->binding))
        return 0;

    fixed[0] = PVIA_MC_LINEAR_BINDING_DOMAIN;
    fixed[1] = linear->source_count;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, fixed, sizeof(fixed));

    for (i = 0; i < linear->source_count; ++i) {
        pvia_mc_linear_source_view source;
        pvia_mc_vss_local_view local;
        pvia_mc_field_element source_value = {0, 0};
        uint64_t count_word;
        size_t j, dimension;
        if (!pvia_mc_linear_source_next(
                linear, &offset, &source) ||
            !pvia_mc_digest_words_nonzero(source.sharing_binding) ||
            source.coefficient_count == 0 ||
            !pvia_mc_parse_vss_local(
                source.local_vss_words.words,
                source.local_vss_words.word_count, &local) ||
            !pvia_mc_reference_validate_vss_local(&local) ||
            local.participant != expected_participant ||
            !pvia_mc_reference_digest_equal(
                local.transcript_binding, source.sharing_binding) ||
            source.coefficient_count != local.element_count)
            return 0;

        blake3_hasher_update(
            &hasher, source.sharing_binding,
            PVIA_MC_DIGEST_WORDS * sizeof(uint64_t));
        count_word = source.coefficient_count;
        blake3_hasher_update(
            &hasher, &count_word, sizeof(count_word));
        blake3_hasher_update(
            &hasher, source.coefficient_words.words,
            source.coefficient_words.word_count * sizeof(uint64_t));

        dimension = (size_t)local.threshold + 1;
        for (j = 0; j < (size_t)source.coefficient_count; ++j) {
            size_t local_word_index = 2 * (j * dimension);
            pvia_mc_field_element coefficient = {
                source.coefficient_words.words[2 * j],
                source.coefficient_words.words[2 * j + 1]};
            pvia_mc_field_element local_element = {
                local.local_row_words.words[local_word_index],
                local.local_row_words.words[local_word_index + 1]};
            source_value = pvia_mc_reference_field_add(
                source_value,
                pvia_mc_field_mul(coefficient, local_element));
        }
        total = pvia_mc_reference_field_add(total, source_value);
    }
    if (offset != linear->source_words.word_count)
        return 0;

    blake3_hasher_finalize(&hasher, digest, sizeof(digest));
    memcpy(binding, digest, sizeof(binding));
    if (!pvia_mc_reference_digest_equal(
            binding, linear->binding) ||
        !pvia_mc_reference_field_equal(
            total, linear->local_share))
        return 0;
    if (local_share_out) *local_share_out = total;
    return 1;
}

static inline int pvia_mc_reference_statement_binding(
    const pvia_mc_statement_view* statement,
    uint64_t out[PVIA_MC_DIGEST_WORDS]) {
    uint64_t words[5 + 4 * PVIA_MC_DIGEST_WORDS];
    size_t pos = 0, i;
    if (!statement || !out) return 0;
    words[pos++] = PVIA_MC_STATEMENT_BINDING_DOMAIN;
    words[pos++] = statement->sid;
    words[pos++] = statement->checkpoint;
    words[pos++] = statement->multiplication_id;
    words[pos++] = statement->dealer;
    for (i = 0; i < PVIA_MC_DIGEST_WORDS; ++i)
        words[pos++] = statement->lhs_sharing_binding[i];
    for (i = 0; i < PVIA_MC_DIGEST_WORDS; ++i)
        words[pos++] = statement->rhs_sharing_binding[i];
    for (i = 0; i < PVIA_MC_DIGEST_WORDS; ++i)
        words[pos++] = statement->output_sharing_binding[i];
    for (i = 0; i < PVIA_MC_DIGEST_WORDS; ++i)
        words[pos++] = statement->context_binding[i];
    pvia_mc_reference_hash_words(words, pos, out);
    return 1;
}

static inline int pvia_mc_reference_input_share(
    const pvia_mc_word_span* section,
    uint64_t expected_participant,
    const uint64_t* expected_binding,
    pvia_mc_field_element* share_out) {
    pvia_mc_sharing_witness_view envelope;
    if (!section || !expected_binding || !share_out ||
        !pvia_mc_parse_sharing_witness(
            section->words, section->word_count, &envelope) ||
        !pvia_mc_reference_digest_equal(
            envelope.sharing_binding, expected_binding))
        return 0;

    if (envelope.kind == PVIA_MC_SHARING_KIND_VSS_LOCAL) {
        pvia_mc_vss_local_view local;
        if (!pvia_mc_parse_vss_local(
                envelope.payload.words,
                envelope.payload.word_count, &local) ||
            !pvia_mc_reference_validate_vss_local(&local) ||
            local.participant != expected_participant ||
            local.element_count != 1 ||
            !pvia_mc_reference_digest_equal(
                local.transcript_binding, expected_binding) ||
            local.local_row_words.word_count < 2)
            return 0;
        share_out->real = local.local_row_words.words[0];
        share_out->imaginary = local.local_row_words.words[1];
        return 1;
    }

    if (envelope.kind ==
        PVIA_MC_SHARING_KIND_LINEAR_COMBINATION) {
        pvia_mc_linear_view linear;
        if (!pvia_mc_parse_linear(
                envelope.payload.words,
                envelope.payload.word_count, &linear) ||
            !pvia_mc_reference_digest_equal(
                linear.binding, expected_binding))
            return 0;
        return pvia_mc_reference_validate_linear(
            &linear, expected_participant, share_out);
    }
    return 0;
}

static inline int pvia_mc_reference_output_value(
    const pvia_mc_word_span* section,
    uint64_t expected_dealer,
    const uint64_t* expected_binding,
    pvia_mc_field_element* value_out) {
    pvia_mc_sharing_witness_view envelope;
    pvia_mc_vss_dealer_view dealer;
    if (!section || !expected_binding || !value_out ||
        !pvia_mc_parse_sharing_witness(
            section->words, section->word_count, &envelope) ||
        envelope.kind != PVIA_MC_SHARING_KIND_VSS_DEALER ||
        !pvia_mc_reference_digest_equal(
            envelope.sharing_binding, expected_binding) ||
        !pvia_mc_parse_vss_dealer(
            envelope.payload.words,
            envelope.payload.word_count, &dealer) ||
        !pvia_mc_reference_validate_vss_dealer(&dealer) ||
        dealer.dealer != expected_dealer ||
        dealer.element_count != 1 ||
        !pvia_mc_reference_digest_equal(
            dealer.transcript_binding, expected_binding) ||
        dealer.coefficient_words.word_count < 2)
        return 0;
    value_out->real = dealer.coefficient_words.words[0];
    value_out->imaginary = dealer.coefficient_words.words[1];
    return 1;
}

static inline int pvia_mc_reference_validate_relation(
    const uint64_t* statement_words, size_t statement_word_count,
    const uint64_t* witness_words, size_t witness_word_count) {
    pvia_mc_statement_view statement;
    pvia_mc_witness_view witness;
    pvia_mc_field_element lhs, rhs, output, product;
    uint64_t statement_binding[PVIA_MC_DIGEST_WORDS];
    if (!pvia_mc_parse_statement(
            statement_words, statement_word_count, &statement) ||
        !pvia_mc_reference_statement_binding(
            &statement, statement_binding) ||
        !pvia_mc_reference_digest_equal(
            statement_binding, statement.statement_binding) ||
        !pvia_mc_parse_witness(
            witness_words, witness_word_count, &witness) ||
        !pvia_mc_validate_witness_payloads(&witness))
        return 0;

#if !PVIA_MC_FIELD_HELPERS_AVAILABLE
    return 0;
#else
    product = pvia_mc_field_mul(
        witness.lhs_share, witness.rhs_share);
    if (!pvia_mc_reference_field_equal(
            product, witness.product_value))
        return 0;

    if (!pvia_mc_reference_input_share(
            &witness.lhs_section, statement.dealer,
            statement.lhs_sharing_binding, &lhs) ||
        !pvia_mc_reference_input_share(
            &witness.rhs_section, statement.dealer,
            statement.rhs_sharing_binding, &rhs) ||
        !pvia_mc_reference_output_value(
            &witness.output_section, statement.dealer,
            statement.output_sharing_binding, &output))
        return 0;

    return pvia_mc_reference_field_equal(lhs, witness.lhs_share) &&
        pvia_mc_reference_field_equal(rhs, witness.rhs_share) &&
        pvia_mc_reference_field_equal(output, witness.product_value) &&
        pvia_mc_reference_field_equal(
            output, pvia_mc_field_mul(lhs, rhs));
#endif
}

#ifdef __cplusplus
}
#endif

#endif
