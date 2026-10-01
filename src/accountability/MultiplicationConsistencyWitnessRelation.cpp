#include "MultiplicationConsistencyWitnessRelation.hpp"

#include "MultiplicationConsistencySharingWitness.hpp"
#include "ReferenceBivariateVss.hpp"
#include "ReferenceLinearSharingProvenance.hpp"

namespace pvia {
namespace {

bool input_local_share(
    const MultiplicationConsistencySharingWitnessEnvelope& envelope,
    uint32_t dealer, const Digest& expected_binding,
    F* share) {
    if (!share || envelope.sharing_binding != expected_binding)
        return false;
    if (envelope.kind ==
        MultiplicationConsistencySharingWitnessKind::VSS_LOCAL) {
        ReferenceVssLocalWitness direct;
        if (!decode_reference_vss_local_witness(
                envelope.payload_words, &direct) ||
            direct.participant != static_cast<int>(dealer) ||
            direct.element_count != 1 ||
            direct.transcript_binding != expected_binding ||
            direct.local_row_words.size() < 2)
            return false;
        *share = F(
            static_cast<long long>(direct.local_row_words[0]),
            static_cast<long long>(direct.local_row_words[1]));
        return true;
    }
    if (envelope.kind !=
        MultiplicationConsistencySharingWitnessKind::LINEAR_COMBINATION)
        return false;

    ReferenceLinearSharingProvenance linear;
    if (!decode_reference_linear_sharing_provenance(
            envelope.payload_words, &linear) ||
        linear.binding != expected_binding)
        return false;
    for (const auto& source : linear.sources) {
        if (source.local_witness.participant !=
                static_cast<int>(dealer) ||
            source.local_witness.transcript_binding !=
                source.sharing_binding)
            return false;
    }
    *share = linear.local_share;
    return true;
}

bool output_product_value(
    const MultiplicationConsistencySharingWitnessEnvelope& envelope,
    uint32_t dealer, const Digest& expected_binding,
    F* value) {
    if (!value ||
        envelope.kind !=
            MultiplicationConsistencySharingWitnessKind::VSS_DEALER ||
        envelope.sharing_binding != expected_binding)
        return false;
    ReferenceVssDealerWitness output;
    if (!decode_reference_vss_dealer_witness(
            envelope.payload_words, &output) ||
        output.dealer != static_cast<int>(dealer) ||
        output.element_count != 1 ||
        output.transcript_binding != expected_binding ||
        output.coefficient_words.size() < 2)
        return false;
    *value = F(
        static_cast<long long>(output.coefficient_words[0]),
        static_cast<long long>(output.coefficient_words[1]));
    return true;
}

} // namespace

bool validate_multiplication_consistency_provider_witness_relation(
    const MultiplicationConsistencyStatement& statement,
    const MultiplicationConsistencyWitness& witness) {
    if (!validate_multiplication_consistency_witness_for_statement(
            statement, witness))
        return false;

    MultiplicationConsistencySharingWitnessEnvelope lhs;
    MultiplicationConsistencySharingWitnessEnvelope rhs;
    MultiplicationConsistencySharingWitnessEnvelope output;
    if (!decode_multiplication_consistency_sharing_witness(
            witness.lhs_sharing_witness_words, &lhs) ||
        !decode_multiplication_consistency_sharing_witness(
            witness.rhs_sharing_witness_words, &rhs) ||
        !decode_multiplication_consistency_sharing_witness(
            witness.output_sharing_witness_words, &output))
        return false;

    F lhs_share(0);
    F rhs_share(0);
    F output_value(0);
    return input_local_share(
               lhs, statement.dealer, statement.lhs_sharing_binding,
               &lhs_share) &&
        input_local_share(
               rhs, statement.dealer, statement.rhs_sharing_binding,
               &rhs_share) &&
        output_product_value(
               output, statement.dealer,
               statement.output_sharing_binding, &output_value) &&
        lhs_share == witness.lhs_share &&
        rhs_share == witness.rhs_share &&
        output_value == witness.product_value &&
        output_value == lhs_share * rhs_share;
}

} // namespace pvia
