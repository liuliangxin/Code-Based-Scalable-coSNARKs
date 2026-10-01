#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-/home/liuliangxin/Code-Based-Scalable-coSNARKs-main}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/experiments/results/sp1_groth16_candidate_$STAMP}"

export PATH="$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"
cd "$ROOT"
mkdir -p "$OUT"

HOST=experiments/sp1_provider/host/src/lib.rs
HOST_CARGO=experiments/sp1_provider/host/Cargo.toml
RELATION=experiments/sp1_provider/relation/src/lib.rs
PROGRAM=experiments/sp1_provider/program/src/main.rs
ELF=experiments/sp1_provider/elf/pvia-sp1-relation-program
LOCK=experiments/sp1_provider/Cargo.lock
RELEASE_LIB=experiments/sp1_provider/target/release/libpvia_sp1_provider_host.so
CANDIDATE_LIB="$OUT/libpvia_sp1_provider_groth16_candidate.so"

restore_default() {
  cargo build --manifest-path experiments/sp1_provider/Cargo.toml     -p pvia-sp1-provider-host --release     > "$OUT/default_restore.log" 2>&1
}
trap restore_default EXIT

cargo build --manifest-path experiments/sp1_provider/Cargo.toml   -p pvia-sp1-provider-host --release   --features groth16-candidate   > "$OUT/candidate_build.log" 2>&1

cp "$RELEASE_LIB" "$CANDIDATE_LIB"

python3 - "$CANDIDATE_LIB" 1 > "$OUT/candidate_capability.txt" <<'PY'
import ctypes, sys
lib=ctypes.CDLL(sys.argv[1])
expected=int(sys.argv[2])
lib.pvia_mc_provider_abi_version.restype=ctypes.c_uint32
if lib.pvia_mc_provider_abi_version() != 2:
    raise SystemExit("unexpected ABI version")
fn=lib.pvia_mc_provider_capabilities
fn.argtypes=[ctypes.POINTER(ctypes.c_uint64),ctypes.POINTER(ctypes.c_size_t)]
fn.restype=ctypes.c_int
n=ctypes.c_size_t(0)
if fn(None,ctypes.byref(n)) != 1 or n.value != 20:
    raise SystemExit("capability sizing failed")
buf=(ctypes.c_uint64*n.value)()
if fn(buf,ctypes.byref(n)) != 1:
    raise SystemExit("capability read failed")
w=list(buf)
if w[2:7] != [1,1,expected,1,1]:
    raise SystemExit(f"unexpected capability flags: {w[2:7]}")
print("abi_version=2")
print("available=1")
print("strong_soundness=1")
print(f"zero_knowledge={w[4]}")
print("binds_input=1")
print("binds_output=1")
print(f"protocol_id={w[7]}")
print("relation_binding=" + ",".join(str(x) for x in w[8:12]))
print("implementation_binding=" + ",".join(str(x) for x in w[12:16]))
print("capability_binding=" + ",".join(str(x) for x in w[16:20]))
PY

restore_default
trap - EXIT

python3 - "$RELEASE_LIB" 0 > "$OUT/default_capability.txt" <<'PY'
import ctypes, sys
lib=ctypes.CDLL(sys.argv[1])
fn=lib.pvia_mc_provider_capabilities
fn.argtypes=[ctypes.POINTER(ctypes.c_uint64),ctypes.POINTER(ctypes.c_size_t)]
fn.restype=ctypes.c_int
n=ctypes.c_size_t(0)
assert fn(None,ctypes.byref(n)) == 1 and n.value == 20
buf=(ctypes.c_uint64*n.value)()
assert fn(buf,ctypes.byref(n)) == 1
w=list(buf)
expected=int(sys.argv[2])
if w[2:7] != [1,1,expected,1,1]:
    raise SystemExit(f"default capability was not restored: {w[2:7]}")
print(f"zero_knowledge={w[4]}")
print(f"protocol_id={w[7]}")
PY

{
  echo 'SP1_GROTH16_CANDIDATE_BUILD: PASS'
  echo 'candidate_feature=groth16-candidate'
  echo 'proof_mode=groth16'
  echo 'default_privacy_capability=0'
  echo 'candidate_privacy_capability=1'
  echo "host_sha256=$(sha256sum "$HOST" | awk '{print $1}')"
  echo "host_cargo_sha256=$(sha256sum "$HOST_CARGO" | awk '{print $1}')"
  echo "relation_sha256=$(sha256sum "$RELATION" | awk '{print $1}')"
  echo "program_sha256=$(sha256sum "$PROGRAM" | awk '{print $1}')"
  echo "elf_sha256=$(sha256sum "$ELF" | awk '{print $1}')"
  echo "cargo_lock_sha256=$(sha256sum "$LOCK" | awk '{print $1}')"
  echo "candidate_library_sha256=$(sha256sum "$CANDIDATE_LIB" | awk '{print $1}')"
  echo "default_library_sha256=$(sha256sum "$RELEASE_LIB" | awk '{print $1}')"
  echo "candidate_library=$CANDIDATE_LIB"
  echo "results=$OUT"
} | tee "$OUT/SUMMARY.txt"
