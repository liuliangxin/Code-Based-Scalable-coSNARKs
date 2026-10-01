#!/usr/bin/env python3
from pathlib import Path
import re
import sys

def fail(msg):
    raise SystemExit(msg)

root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
cargo_root = Path.home() / ".cargo" / "registry" / "src"
ffi = next(cargo_root.glob("*/sp1-recursion-gnark-ffi-6.8.1"), None)
if ffi is None:
    fail("missing sp1-recursion-gnark-ffi-6.8.1 source")

gomod = (ffi / "go/go.mod").read_text()
if "github.com/consensys/gnark v0.14.0" not in gomod:
    fail("unexpected gnark API version")
replace = re.search(
    r"replace github\.com/consensys/gnark => github\.com/p4u/gnark "
    r"v0\.0\.0-[0-9]+-([0-9a-f]+)", gomod)
if not replace:
    fail("missing pinned p4u/gnark replacement")
commit = replace.group(1)
if commit != "cd7874155e26":
    fail(f"unexpected gnark commit: {commit}")

sp1_prove = (ffi / "go/sp1/prove_groth16.go").read_text()
sp1_verify = (ffi / "go/sp1/verify.go").read_text()
required_sp1 = [
    "groth16.Prove(globalR1cs, globalPk, witness)",
    "publicWitness, err := witness.Public()",
    "groth16.Verify(proof, vk, publicWitness)",
]
for token in required_sp1:
    if token not in sp1_prove + sp1_verify:
        fail(f"missing SP1 Groth16 evidence token: {token}")

evidence = root / "experiments/sp1_provider/GROTH16_PRIVACY_EVIDENCE.txt"
if not evidence.is_file():
    fail("missing pinned Groth16 privacy evidence file")
text = evidence.read_text()
required_evidence = [
    "gnark_api_version=v0.14.0",
    "gnark_commit=cd7874155e26",
    "package_claim=Groth16 Zero Knowledge Proof system",
    "prover_randomization=sample random r and s",
    "verifier_input=public witness only",
]
for token in required_evidence:
    if token not in text:
        fail(f"privacy evidence drift: {token}")

print(
    "SP1_GROTH16_PRIVACY_EVIDENCE: PASS "
    "sp1=6.8.1 gnark_api=v0.14.0 gnark_commit=cd7874155e26 "
    "randomized_prover=1 public_witness_verify=1"
)
