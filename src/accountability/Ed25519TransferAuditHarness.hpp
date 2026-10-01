#pragma once

#include "AuditBackend.hpp"
#include "Ed25519PublicTransferCheckBackend.hpp"
#include "PublicTransferObservation.hpp"

#include <vector>

namespace pvia {

bool run_ed25519_transfer_no_framing_selftest(
    int rank, int world_size);

// Development harness for exercising the concrete public-transfer backend on
// real protocol traffic without pretending the private/recovery/proof lanes
// are instantiated. All non-transfer audit actions fail closed.
class Ed25519TransferAuditHarness final : public AuditBackend {
public:
    void OnObservePublicTransfer(
        const PublicTransferObservation& observation) override;

    bool RunSelfCheck(int rank, int world_size) const;
    size_t local_observation_count() const { return observations_.size(); }

    BatchCheckResult BatchCheck(const ObligationSet& scope) const override;
    Violation Dispute(const ObligationSet& scope,
                      const BatchCheckResult& batch) const override;
    RecoverableAuditShare RecoverAudit(
        const Violation& violation) const override;
    BlameCertificate LiftBlame(
        const Violation& violation,
        const RecoverableAuditShare& audit) const override;
    bool Judge(const BlameCertificate& certificate,
               uint64_t expected_session_id) const override;

private:
    std::vector<PublicTransferObservation> observations_;
    Ed25519PublicTransferCheckBackend transfer_backend_;
};

} // namespace pvia
