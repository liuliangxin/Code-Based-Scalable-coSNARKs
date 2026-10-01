#!/usr/bin/env python3
import argparse
import ctypes
import time
from pathlib import Path

CAP_DOMAIN = 0x50564D4343544142
ABI_VERSION = 2
CAP_WORDS = 20

def parse_vector(path: Path):
    lines = path.read_text().splitlines()
    if not lines or lines[0] != "PVIA_MC_PROVIDER_RELATION_VECTOR_V1":
        raise SystemExit("bad vector magic")
    data = {}
    for line in lines[1:]:
        if "=" in line:
            k, v = line.split("=", 1)
            data[k] = v
    statement = [int(x) for x in data["statement_words"].split(",") if x]
    witness = [int(x) for x in data["witness_words"].split(",") if x]
    relation_hex = bytes.fromhex(data["relation_binding"])
    relation_words = [
        int.from_bytes(relation_hex[i:i+8], "little")
        for i in range(0, 32, 8)
    ]
    return data, statement, witness, relation_words

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, required=True)
    ap.add_argument("--vector", type=Path)
    ap.add_argument("--full", action="store_true")
    args = ap.parse_args()

    lib = ctypes.CDLL(str(args.library.resolve()))
    lib.pvia_mc_provider_abi_version.restype = ctypes.c_uint32

    size_p = ctypes.POINTER(ctypes.c_size_t)
    u64_p = ctypes.POINTER(ctypes.c_uint64)
    lib.pvia_mc_provider_capabilities.argtypes = [u64_p, size_p]
    lib.pvia_mc_provider_capabilities.restype = ctypes.c_int
    lib.pvia_mc_provider_prove.argtypes = [
        u64_p, ctypes.c_size_t, u64_p, ctypes.c_size_t, u64_p, size_p
    ]
    lib.pvia_mc_provider_prove.restype = ctypes.c_int
    lib.pvia_mc_provider_verify.argtypes = [
        u64_p, ctypes.c_size_t, u64_p, ctypes.c_size_t
    ]
    lib.pvia_mc_provider_verify.restype = ctypes.c_int

    version = lib.pvia_mc_provider_abi_version()
    if version != ABI_VERSION:
        raise SystemExit(f"ABI version mismatch: {version}")

    count = ctypes.c_size_t(0)
    if lib.pvia_mc_provider_capabilities(None, ctypes.byref(count)) != 1:
        raise SystemExit("capability size query failed")
    if count.value != CAP_WORDS:
        raise SystemExit(f"capability word count mismatch: {count.value}")
    cap = (ctypes.c_uint64 * count.value)()
    actual = ctypes.c_size_t(count.value)
    if lib.pvia_mc_provider_capabilities(cap, ctypes.byref(actual)) != 1:
        raise SystemExit("capability read failed")
    words = list(cap)
    if words[0] != CAP_DOMAIN or words[1] != ABI_VERSION:
        raise SystemExit("capability header mismatch")
    if words[2:7] != [1, 1, 1, 1, 1]:
        raise SystemExit(f"unexpected capability flags: {words[2:7]}")
    if words[7] == 0:
        raise SystemExit("protocol id is zero")

    vector = None
    if args.vector:
        vector = parse_vector(args.vector)
        if words[8:12] != vector[3]:
            raise SystemExit("relation binding mismatch")

    print(
        "SP1_PROVIDER_CAPABILITIES: PASS "
        f"abi={version} protocol_id={words[7]} "
        f"zero_knowledge={words[4]}"
    )

    if not args.full:
        return
    if vector is None:
        raise SystemExit("--full requires --vector")

    _, statement, witness, _ = vector
    StatementArray = ctypes.c_uint64 * len(statement)
    WitnessArray = ctypes.c_uint64 * len(witness)
    statement_arr = StatementArray(*statement)
    witness_arr = WitnessArray(*witness)

    proof_count = ctypes.c_size_t(0)
    start = time.monotonic()
    rc = lib.pvia_mc_provider_prove(
        statement_arr, len(statement),
        witness_arr, len(witness),
        None, ctypes.byref(proof_count),
    )
    prove_seconds = time.monotonic() - start
    if rc != 1 or proof_count.value == 0:
        raise SystemExit(
            f"proof size query failed rc={rc} count={proof_count.value}"
        )

    ProofArray = ctypes.c_uint64 * proof_count.value
    proof_arr = ProofArray()
    actual = ctypes.c_size_t(proof_count.value)
    start = time.monotonic()
    rc = lib.pvia_mc_provider_prove(
        statement_arr, len(statement),
        witness_arr, len(witness),
        proof_arr, ctypes.byref(actual),
    )
    copy_seconds = time.monotonic() - start
    if rc != 1 or actual.value != proof_count.value:
        raise SystemExit(
            f"proof output failed rc={rc} actual={actual.value}"
        )

    start = time.monotonic()
    verify_rc = lib.pvia_mc_provider_verify(
        statement_arr, len(statement), proof_arr, actual.value
    )
    verify_seconds = time.monotonic() - start
    if verify_rc != 1:
        raise SystemExit(f"proof verification failed rc={verify_rc}")

    proof_words = list(proof_arr)
    if len(proof_words) < 17 or proof_words[2] != 1:
        raise SystemExit("outer proof status mismatch")

    print(
        "SP1_PROVIDER_CORE_PROOF: PASS "
        f"proof_words={actual.value} "
        f"prove_seconds={prove_seconds:.3f} "
        f"copy_seconds={copy_seconds:.3f} "
        f"verify_seconds={verify_seconds:.3f}"
    )

if __name__ == "__main__":
    main()
