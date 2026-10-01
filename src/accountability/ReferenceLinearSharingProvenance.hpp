#pragma once

#include "ReferenceBivariateVss.hpp"

#include <vector>

namespace pvia {

struct ReferenceLinearSharingSource {
    Digest sharing_binding{};
    std::vector<F> element_coefficients;
    ReferenceVssLocalWitness local_witness{};
};

struct ReferenceLinearSharingProvenance {
    bool available = false;
    F local_share{};
    std::vector<ReferenceLinearSharingSource> sources;
    Digest binding{};
};

Digest compute_reference_linear_sharing_binding(
    const std::vector<ReferenceLinearSharingSource>& sources);
bool build_reference_linear_sharing_provenance(
    std::vector<ReferenceLinearSharingSource> sources,
    ReferenceLinearSharingProvenance* provenance);

bool validate_reference_linear_sharing_provenance(
    const ReferenceLinearSharingProvenance& provenance);

std::vector<u64> encode_reference_linear_sharing_provenance(
    const ReferenceLinearSharingProvenance& provenance);

bool decode_reference_linear_sharing_provenance(
    const std::vector<u64>& words,
    ReferenceLinearSharingProvenance* provenance);

} // namespace pvia
