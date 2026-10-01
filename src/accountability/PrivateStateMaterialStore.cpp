#include "PrivateStateMaterialStore.hpp"

namespace pvia {

PrivateStateMaterial& PrivateStateMaterialStore::Ensure(
    const AuditStateView& state) {
    for (auto& item : states_) {
        if (item.state.id == state.id) {
            item.state = state;
            return item;
        }
    }
    states_.push_back(PrivateStateMaterial{});
    states_.back().state = state;
    return states_.back();
}

void PrivateStateMaterialStore::RegisterMetadata(
    const AuditStateView& state) {
    Ensure(state);
}

void PrivateStateMaterialStore::BindPrivateState(
    const AuditStateView& state,
    const std::vector<F>& local_share) {
    PrivateStateMaterial& material = Ensure(state);
    material.local_share = local_share;
    material.has_private_share = true;
}

bool PrivateStateMaterialStore::BindAuthentication(
    const AuditStateView& state, uint64_t scheme_id,
    const Digest& authentication_binding) {
    if (scheme_id == 0 || authentication_binding == Digest{}) return false;
    PrivateStateMaterial& material = Ensure(state);
    if (material.has_authentication) {
        return material.authentication_scheme_id == scheme_id &&
               material.authentication_binding == authentication_binding;
    }
    material.authentication_scheme_id = scheme_id;
    material.authentication_binding = authentication_binding;
    material.has_authentication = true;
    return true;
}
PrivateStateMaterial* PrivateStateMaterialStore::Find(StateId id) {
    for (auto& item : states_) {
        if (item.state.id == id) return &item;
    }
    return nullptr;
}

const PrivateStateMaterial* PrivateStateMaterialStore::Find(StateId id) const {
    for (const auto& item : states_) {
        if (item.state.id == id) return &item;
    }
    return nullptr;
}

bool PrivateStateMaterialStore::VerifyDigest(StateId id) const {
    const PrivateStateMaterial* material = Find(id);
    if (!material || !material->has_private_share) return false;
    return hash_field_vector(material->local_share) == material->state.digest;
}

bool PrivateStateMaterialStore::VerifyAuthentication(StateId id) const {
    const PrivateStateMaterial* material = Find(id);
    return material && material->has_authentication &&
        material->authentication_scheme_id != 0 &&
        material->authentication_binding != Digest{};
}

} // namespace pvia
