#include "KernelResidualFamilies.hpp"

namespace pvia {

bool SumcheckKernelResidualEvaluator::Supports(
    AuditRelationKernel kernel) const {
    using K = AuditRelationKernel;
    switch (kernel) {
        case K::COSUMCHECK_ZERO:
        case K::COSUMCHECK_QUADRATIC:
        case K::COSUMCHECK_BATCH:
        case K::DSC_QUADRATIC:
        case K::DSC_CUBIC:
        case K::DSC_SPARROW_QUADRATIC:
        case K::DSC_SPARROW_CUBIC:
        case K::PCS_OPEN_ROUND:
        case K::PCS_BATCH_OPEN_ROUND:
            return true;
        default:
            return false;
    }
}

bool EncodingKernelResidualEvaluator::Supports(
    AuditRelationKernel kernel) const {
    using K = AuditRelationKernel;
    return kernel == K::ENCODING_FIRST_STAGE ||
           kernel == K::ENCODING_ASSEMBLE ||
           kernel == K::ENCODING_STAGE2 ||
           kernel == K::ENCODING_DIRECT_STAGE2;
}
bool CommitFoldOpenKernelResidualEvaluator::Supports(
    AuditRelationKernel kernel) const {
    using K = AuditRelationKernel;
    return kernel == K::ORACLE_MERKLE_COMMIT ||
           kernel == K::FOLD_RS ||
           kernel == K::OPEN_QUERY;
}

bool ProductSparseKernelResidualEvaluator::Supports(
    AuditRelationKernel kernel) const {
    using K = AuditRelationKernel;
    return kernel == K::PRODUCT_FRONTIER ||
           kernel == K::SPARSE_TRANSCRIPT;
}

bool AggregationKernelResidualEvaluator::Supports(
    AuditRelationKernel kernel) const {
    using K = AuditRelationKernel;
    return kernel == K::AGGREGATE_CODED ||
           kernel == K::AGGREGATE_WEIGHTED ||
           kernel == K::AGGREGATE_BATCH ||
           kernel == K::PUBLISH_AGGREGATE;
}

} // namespace pvia
