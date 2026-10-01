# SP1 multiplication-consistency provider candidate

This directory contains a concrete SP1 6.8.1 implementation of the canonical
multiplication-consistency relation used by the repository.

Current status:

- relation/ independently implements ABI v2 statement/witness parsing,
  VSS provenance checks, linear-provenance checks, field arithmetic, BLAKE3
  bindings, and the final multiplication relation in Rust.
- The Rust relation implementation passes the repository's canonical
  vss_local and linear conformance vectors.
- program/ executes that same relation inside the SP1 guest and commits only
  the ABI version, relation binding, and canonical statement binding.
- host/ embeds the Docker-built guest ELF and exports the four required C ABI
  symbols as a cdylib.
- Proof-system ID: 68101.
- SP1 version: 6.8.1.
- Guest builds use the official SP1 Docker build path because the host system's
  GLIBC is older than the prebuilt SP1 guest compiler requires.

The default build remains fail-closed: the repository proof mode is Groth16,
but DEFAULT_PRODUCTION_PRIVACY_CONFIRMED is false, so the default shared
library reports privacy_capability=0. An explicit groth16-candidate Cargo
feature builds a separate candidate library with privacy_capability=1 without
changing the default build. The candidate builder restores the default release
library before it exits and records source, ELF, lockfile, and library hashes.
A successful candidate build therefore does not by itself change the two
remaining PARTIAL paper-alignment obligations.

Build and structural check:

  BUILD_GUEST=0 bash experiments/build_sp1_provider_xfusion.sh

Rebuild the guest ELF in Docker:

  BUILD_GUEST=1 bash experiments/build_sp1_provider_xfusion.sh

Build a reproducible Groth16 candidate while restoring the default library:

  bash experiments/build_sp1_groth16_candidate_xfusion.sh
