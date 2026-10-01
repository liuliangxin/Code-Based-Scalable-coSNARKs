#pragma once

#include "PVIA.hpp"

#include <vector>

namespace pvia {

struct PrivateStateMaterial {
    AuditStateView state{};
    std::vector<F> local_share;
    uint64_t authentication_scheme_id = 0;
    Digest authentication_binding{};
    bool has_private_share = false;
    bool has_authentication = false;
};

class PrivateStateMaterialStore {
public:
    void RegisterMetadata(const AuditStateView& state);
    void BindPrivateState(
        const AuditStateView& state,
        const std::vector<F>& local_share);
    bool BindAuthentication(
        const AuditStateView& state, uint64_t scheme_id,
        const Digest& authentication_binding);

    PrivateStateMaterial* Find(StateId id);
    const PrivateStateMaterial* Find(StateId id) const;
    bool VerifyDigest(StateId id) const;
    bool VerifyAuthentication(StateId id) const;

private:
    PrivateStateMaterial& Ensure(const AuditStateView& state);
    std::vector<PrivateStateMaterial> states_;
};

} // namespace pvia
