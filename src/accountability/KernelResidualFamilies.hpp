#pragma once

#include "KernelResidualEvaluator.hpp"

namespace pvia {

// Family adapters keep the provider-facing registry small while allowing a
// concrete backend to implement different MPC/ZK machinery per protocol layer.
class SumcheckKernelResidualEvaluator : public KernelResidualEvaluator {
public:
    bool Supports(AuditRelationKernel kernel) const final;
    PrivateResidualHandle Evaluate(
        const KernelResidualContext& context) const final {
        return EvaluateSumcheck(context);
    }
protected:
    virtual PrivateResidualHandle EvaluateSumcheck(
        const KernelResidualContext& context) const = 0;
};

class EncodingKernelResidualEvaluator : public KernelResidualEvaluator {
public:
    bool Supports(AuditRelationKernel kernel) const final;
    PrivateResidualHandle Evaluate(
        const KernelResidualContext& context) const final {
        return EvaluateEncoding(context);
    }
protected:
    virtual PrivateResidualHandle EvaluateEncoding(
        const KernelResidualContext& context) const = 0;
};
class CommitFoldOpenKernelResidualEvaluator : public KernelResidualEvaluator {
public:
    bool Supports(AuditRelationKernel kernel) const final;
    PrivateResidualHandle Evaluate(
        const KernelResidualContext& context) const final {
        return EvaluateCommitFoldOpen(context);
    }
protected:
    virtual PrivateResidualHandle EvaluateCommitFoldOpen(
        const KernelResidualContext& context) const = 0;
};

class ProductSparseKernelResidualEvaluator : public KernelResidualEvaluator {
public:
    bool Supports(AuditRelationKernel kernel) const final;
    PrivateResidualHandle Evaluate(
        const KernelResidualContext& context) const final {
        return EvaluateProductSparse(context);
    }
protected:
    virtual PrivateResidualHandle EvaluateProductSparse(
        const KernelResidualContext& context) const = 0;
};

class AggregationKernelResidualEvaluator : public KernelResidualEvaluator {
public:
    bool Supports(AuditRelationKernel kernel) const final;
    PrivateResidualHandle Evaluate(
        const KernelResidualContext& context) const final {
        return EvaluateAggregationKernel(context);
    }
protected:
    virtual PrivateResidualHandle EvaluateAggregationKernel(
        const KernelResidualContext& context) const = 0;
};

} // namespace pvia
