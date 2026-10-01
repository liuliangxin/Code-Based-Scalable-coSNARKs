#!/usr/bin/env python3
import argparse
import ctypes
import struct
from pathlib import Path

MAGIC = "PVIA_MC_PROVIDER_RELATION_VECTOR_V1"

def parse_vector(path: Path):
    lines = path.read_text().splitlines()
    if not lines or lines[0] != MAGIC:
        raise SystemExit("bad vector magic")
    kv = {}
    for line in lines[1:]:
        if "=" not in line:
            raise SystemExit("malformed vector line")
        k, v = line.split("=", 1)
        kv[k] = v
    statement = [int(x) for x in kv["statement_words"].split(",") if x]
    witness = [int(x) for x in kv["witness_words"].split(",") if x]
    return statement, witness

def u64_array(values):
    arr_t = ctypes.c_uint64 * len(values)
    return arr_t(*values)

def load_lib(path: Path):
    lib = ctypes.CDLL(str(path))
    lib.pvia_mc_provider_abi_version.argtypes = []
    lib.pvia_mc_provider_abi_version.restype = ctypes.c_uint32

    lib.pvia_mc_provider_capabilities.argtypes = [
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.pvia_mc_provider_capabilities.restype = ctypes.c_int

    lib.pvia_mc_provider_prove.argtypes = [
        ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.pvia_mc_provider_prove.restype = ctypes.c_int

    lib.pvia_mc_provider_verify.argtypes = [
        ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t,
    ]
    lib.pvia_mc_provider_verify.restype = ctypes.c_int
    return lib

def capability_words(lib):
    count = ctypes.c_size_t(0)
    if lib.pvia_mc_provider_capabilities(None, ctypes.byref(count)) != 1:
        raise SystemExit("capability sizing failed")
    out_t = ctypes.c_uint64 * count.value
    out = out_t()
    cap = ctypes.c_size_t(count.value)
    if lib.pvia_mc_provider_capabilities(out, ctypes.byref(cap)) != 1:
        raise SystemExit("capability write failed")
    return list(out[:cap.value])

def prove(args):
    statement, witness = parse_vector(args.vector)
    lib = load_lib(args.library)
    if lib.pvia_mc_provider_abi_version() != 2:
        raise SystemExit("unexpected provider ABI version")

    caps = capability_words(lib)
    if len(caps) != 20:
        raise SystemExit("capability word count mismatch")
    if (
        args.expected_zero_knowledge is not None
        and caps[4] != args.expected_zero_knowledge
    ):
        raise SystemExit(
            f"zero-knowledge capability mismatch: "
            f"expected {args.expected_zero_knowledge}, got {caps[4]}")

    s = u64_array(statement)
    w = u64_array(witness)
    count = ctypes.c_size_t(0)
    if lib.pvia_mc_provider_prove(
        s, len(statement), w, len(witness),
        None, ctypes.byref(count)) != 1:
        raise SystemExit("proof sizing/generation failed")
    if count.value <= 17:
        raise SystemExit("proof artifact is too short")

    out_t = ctypes.c_uint64 * count.value
    out = out_t()
    out_count = ctypes.c_size_t(count.value)
    if lib.pvia_mc_provider_prove(
        s, len(statement), w, len(witness),
        out, ctypes.byref(out_count)) != 1:
        raise SystemExit("proof artifact write failed")

    words = list(out[:out_count.value])
    args.artifact.parent.mkdir(parents=True, exist_ok=True)
    with args.artifact.open("wb") as f:
        for word in words:
            f.write(struct.pack("<Q", word))
    print(
        "SP1_C_ABI_PROVE: PASS "
        f"words={len(words)} bytes={len(words)*8} "
        f"zero_knowledge_declared={caps[4]}"
    )

def verify(args):
    statement, _ = parse_vector(args.vector)
    data = args.artifact.read_bytes()
    if len(data) == 0 or len(data) % 8 != 0:
        raise SystemExit("bad artifact byte length")
    proof = list(struct.unpack("<" + "Q" * (len(data)//8), data))
    lib = load_lib(args.library)
    s = u64_array(statement)
    p = u64_array(proof)
    ok = lib.pvia_mc_provider_verify(s, len(statement), p, len(proof))
    if ok != 1:
        raise SystemExit("provider verify failed")
    print(f"SP1_C_ABI_VERIFY: PASS words={len(proof)}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["prove", "verify"])
    ap.add_argument("--library", type=Path, required=True)
    ap.add_argument("--vector", type=Path, required=True)
    ap.add_argument("--artifact", type=Path, required=True)
    ap.add_argument(
        "--expected-zero-knowledge",
        type=int, choices=[0, 1])
    args = ap.parse_args()
    if args.mode == "prove":
        prove(args)
    else:
        verify(args)

if __name__ == "__main__":
    main()
