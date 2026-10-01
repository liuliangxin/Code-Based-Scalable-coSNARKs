#pragma once

#include "PVIA.hpp"

namespace pvia {

// Development-only public adjudicator.  It intentionally accepts only the
// self-contained blame certificate and an expected session id; no witness,
// secret share, MPI state, or Runtime internals are available to the judge.
class PublicJudge {
public:
    static Digest compute_debug_proof_digest(const BlameCertificate& cert);
    static bool VerifyDebug(const BlameCertificate& cert,
                            uint64_t expected_session_id);
};

} // namespace pvia
