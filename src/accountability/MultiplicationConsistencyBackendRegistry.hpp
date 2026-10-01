#pragma once

#include "MultiplicationConsistencyProof.hpp"
#include "MultiplicationConsistencyProviderAcceptance.hpp"

namespace pvia {

// Process-local installation point for an accepted multiplication-consistency
// provider. The registry is empty by default. A provider becomes visible only
// after the distributed acceptance result is complete and matches the
// provider's capability binding. Installed providers are caller-owned and
// must outlive their registration.
class MultiplicationConsistencyBackendRegistry final {
public:
    static bool AcceptanceMatches(
        const MultiplicationConsistencyProofBackend* backend,
        const MultiplicationConsistencyProviderAcceptanceResult* acceptance) {
        if (!backend || !acceptance ||
            !acceptance->available ||
            !acceptance->capabilities_ready ||
            !acceptance->multiplication_verified ||
            !acceptance->zero_case_verified ||
            !acceptance->nonzero_case_verified ||
            acceptance->acceptance_binding == Digest{} ||
            acceptance->capability_binding == Digest{})
            return false;
        const auto capabilities = backend->Capabilities();
        return
            production_ready_multiplication_consistency_capabilities(
                capabilities) &&
            capabilities.capability_binding ==
                acceptance->capability_binding;
    }

    static bool InstallAccepted(
        const MultiplicationConsistencyProofBackend* backend,
        const MultiplicationConsistencyProviderAcceptanceResult& acceptance) {
        if (!AcceptanceMatches(backend, &acceptance))
            return false;
        state().backend = backend;
        state().acceptance_binding = acceptance.acceptance_binding;
        return true;
    }

    static const MultiplicationConsistencyProofBackend* Current() {
        return state().backend;
    }

    static Digest CurrentAcceptanceBinding() {
        return state().acceptance_binding;
    }

    static void Clear() {
        state() = State{};
    }

private:
    struct State {
        const MultiplicationConsistencyProofBackend* backend = nullptr;
        Digest acceptance_binding{};
    };

    static State& state() {
        static State current;
        return current;
    }

    static void Restore(
        const MultiplicationConsistencyProofBackend* backend,
        const Digest& acceptance_binding) {
        state().backend = backend;
        state().acceptance_binding = acceptance_binding;
    }

    friend class ScopedMultiplicationConsistencyBackendRegistration;
};

class ScopedMultiplicationConsistencyBackendRegistration final {
public:
    ScopedMultiplicationConsistencyBackendRegistration(
        const MultiplicationConsistencyProofBackend* backend,
        const MultiplicationConsistencyProviderAcceptanceResult* acceptance)
        : previous_backend_(
              MultiplicationConsistencyBackendRegistry::Current()),
          previous_acceptance_binding_(
              MultiplicationConsistencyBackendRegistry::
                  CurrentAcceptanceBinding()) {
        if (!backend || !acceptance) return;
        active_ =
            MultiplicationConsistencyBackendRegistry::InstallAccepted(
                backend, *acceptance);
    }

    ~ScopedMultiplicationConsistencyBackendRegistration() {
        if (!active_) return;
        MultiplicationConsistencyBackendRegistry::Restore(
            previous_backend_, previous_acceptance_binding_);
    }

    ScopedMultiplicationConsistencyBackendRegistration(
        const ScopedMultiplicationConsistencyBackendRegistration&) = delete;
    ScopedMultiplicationConsistencyBackendRegistration& operator=(
        const ScopedMultiplicationConsistencyBackendRegistration&) = delete;

    bool active() const { return active_; }

private:
    const MultiplicationConsistencyProofBackend* previous_backend_ = nullptr;
    Digest previous_acceptance_binding_{};
    bool active_ = false;
};

} // namespace pvia
