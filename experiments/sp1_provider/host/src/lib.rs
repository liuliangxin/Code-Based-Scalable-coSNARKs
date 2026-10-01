use pvia_mc_relation::{
    relation_binding, statement_binding_from_words, validate_relation,
    RelationInput, RelationPublicValues, ABI_VERSION,
};
use sp1_sdk::{
    blocking::{CpuProver, ProveRequest, Prover, ProverClient},
    Elf, ProvingKey, SP1ProofWithPublicValues, SP1Stdin,
};

use std::{
    ptr,
    slice,
};

const RELATION_ELF_BYTES: &[u8] =
    include_bytes!("../../elf/pvia-sp1-relation-program");

pub const PVIA_SP1_PROOF_SYSTEM_ID: u32 = 68_101;
pub const PVIA_SP1_PROTOCOL_ID: u64 = 0x5350315f56363831;
pub const PVIA_SP1_PROVIDER_PROOF_MODE: &str = "groth16";

const DIGEST_WORDS: usize = 4;
const CAPABILITY_WORDS: usize = 20;
const PROOF_HEADER_WORDS: usize = 17;

const CAPABILITY_ABI_DOMAIN: u64 = 0x50564d4343544142;
const CAPABILITY_BINDING_DOMAIN: u64 = 0x50564d554c434150;
const PROOF_COMMITMENT_DOMAIN: u64 = 0x50564d554c505246;

const CAP_DOMAIN_INDEX: usize = 0;
const CAP_VERSION_INDEX: usize = 1;
const CAP_AVAILABLE_INDEX: usize = 2;
const CAP_STRONG_SOUNDNESS_INDEX: usize = 3;
const CAP_ZERO_KNOWLEDGE_INDEX: usize = 4;
const CAP_BINDS_INPUT_INDEX: usize = 5;
const CAP_BINDS_OUTPUT_INDEX: usize = 6;
const CAP_PROTOCOL_ID_INDEX: usize = 7;
const CAP_RELATION_BINDING_INDEX: usize = 8;
const CAP_IMPLEMENTATION_BINDING_INDEX: usize = 12;
const CAP_CAPABILITY_BINDING_INDEX: usize = 16;

const PROOF_AVAILABLE_INDEX: usize = 0;
const PROOF_AUTHENTICATED_INDEX: usize = 1;
const PROOF_ZERO_KNOWLEDGE_INDEX: usize = 2;
const PROOF_SYSTEM_ID_INDEX: usize = 3;
const PROOF_STATEMENT_BINDING_INDEX: usize = 4;
const PROOF_TRANSCRIPT_BINDING_INDEX: usize = 8;
const PROOF_COMMITMENT_INDEX: usize = 12;
const PROOF_WORD_COUNT_INDEX: usize = 16;

/*
 * The SP1 relation backend is implemented and independently testable.
 * This bit remains false until the selected SP1 proof mode is explicitly
 * accepted for the paper's production privacy requirement.
 */
const DEFAULT_PRODUCTION_PRIVACY_CONFIRMED: bool = false;

#[cfg(feature = "groth16-candidate")]
const PRODUCTION_PRIVACY_CONFIRMED: bool = true;

#[cfg(not(feature = "groth16-candidate"))]
const PRODUCTION_PRIVACY_CONFIRMED: bool =
    DEFAULT_PRODUCTION_PRIVACY_CONFIRMED;

fn relation_elf() -> Elf {
    Elf::Static(RELATION_ELF_BYTES)
}

fn digest_from_bytes(bytes: &[u8]) -> Option<[u64; DIGEST_WORDS]> {
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u64; DIGEST_WORDS];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[8 * i..8 * i + 8]);
        *slot = u64::from_le_bytes(limb);
    }
    Some(out)
}

fn hash_raw(bytes: &[u8]) -> [u64; DIGEST_WORDS] {
    let digest = blake3::hash(bytes);
    digest_from_bytes(digest.as_bytes()).expect("blake3 digest length")
}

fn update_words(hasher: &mut blake3::Hasher, words: &[u64]) {
    for &word in words {
        hasher.update(&word.to_le_bytes());
    }
}

fn hash_words(words: &[u64]) -> [u64; DIGEST_WORDS] {
    let mut hasher = blake3::Hasher::new();
    update_words(&mut hasher, words);
    digest_from_bytes(hasher.finalize().as_bytes())
        .expect("blake3 digest length")
}

fn digest_nonzero(digest: &[u64]) -> bool {
    digest.len() == DIGEST_WORDS && digest.iter().any(|&word| word != 0)
}

fn implementation_binding() -> [u64; DIGEST_WORDS] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PVIA_SP1_PROVIDER_IMPL_V1");
    hasher.update(b"sp1-6.8.1");
    hasher.update(PVIA_SP1_PROVIDER_PROOF_MODE.as_bytes());
    hasher.update(RELATION_ELF_BYTES);
    digest_from_bytes(hasher.finalize().as_bytes())
        .expect("blake3 digest length")
}

fn capability_binding(
    available: u64,
    strong_soundness: u64,
    zero_knowledge: u64,
    binds_input: u64,
    binds_output: u64,
    protocol_id: u64,
    relation: &[u64; DIGEST_WORDS],
    implementation: &[u64; DIGEST_WORDS],
) -> [u64; DIGEST_WORDS] {
    let mut words = vec![
        CAPABILITY_BINDING_DOMAIN,
        available,
        strong_soundness,
        zero_knowledge,
        binds_input,
        binds_output,
        protocol_id,
    ];
    words.extend_from_slice(relation);
    words.extend_from_slice(implementation);
    hash_words(&words)
}

fn capability_words() -> [u64; CAPABILITY_WORDS] {
    let relation = relation_binding();
    let implementation = implementation_binding();
    let available = 1u64;
    let strong = 1u64;
    let privacy = u64::from(PRODUCTION_PRIVACY_CONFIRMED);
    let binds_input = 1u64;
    let binds_output = 1u64;
    let capability = capability_binding(
        available,
        strong,
        privacy,
        binds_input,
        binds_output,
        PVIA_SP1_PROTOCOL_ID,
        &relation,
        &implementation,
    );

    let mut words = [0u64; CAPABILITY_WORDS];
    words[CAP_DOMAIN_INDEX] = CAPABILITY_ABI_DOMAIN;
    words[CAP_VERSION_INDEX] = ABI_VERSION as u64;
    words[CAP_AVAILABLE_INDEX] = available;
    words[CAP_STRONG_SOUNDNESS_INDEX] = strong;
    words[CAP_ZERO_KNOWLEDGE_INDEX] = privacy;
    words[CAP_BINDS_INPUT_INDEX] = binds_input;
    words[CAP_BINDS_OUTPUT_INDEX] = binds_output;
    words[CAP_PROTOCOL_ID_INDEX] = PVIA_SP1_PROTOCOL_ID;
    words[CAP_RELATION_BINDING_INDEX..CAP_RELATION_BINDING_INDEX + DIGEST_WORDS]
        .copy_from_slice(&relation);
    words[CAP_IMPLEMENTATION_BINDING_INDEX
        ..CAP_IMPLEMENTATION_BINDING_INDEX + DIGEST_WORDS]
        .copy_from_slice(&implementation);
    words[CAP_CAPABILITY_BINDING_INDEX
        ..CAP_CAPABILITY_BINDING_INDEX + DIGEST_WORDS]
        .copy_from_slice(&capability);
    words
}

fn public_values_from_proof(
    proof: &SP1ProofWithPublicValues,
) -> Option<RelationPublicValues> {
    let mut public_values = proof.public_values.clone();
    let decoded = std::panic::catch_unwind(
        std::panic::AssertUnwindSafe(|| public_values.read::<RelationPublicValues>()),
    )
    .ok()?;
    Some(decoded)
}

fn expected_public_values(
    statement_words: &[u64],
) -> Option<RelationPublicValues> {
    Some(RelationPublicValues {
        abi_version: ABI_VERSION,
        relation_binding: relation_binding(),
        statement_binding: statement_binding_from_words(statement_words)?,
    })
}

fn public_values_match_statement(
    proof: &SP1ProofWithPublicValues,
    statement_words: &[u64],
) -> bool {
    match (
        public_values_from_proof(proof),
        expected_public_values(statement_words),
    ) {
        (Some(actual), Some(expected)) => actual == expected,
        _ => false,
    }
}

fn transcript_binding(
    proof: &SP1ProofWithPublicValues,
) -> [u64; DIGEST_WORDS] {
    hash_raw(proof.public_values.as_slice())
}

fn bytes_to_words(bytes: &[u8]) -> Vec<u64> {
    let mut words = Vec::with_capacity(1 + bytes.len().div_ceil(8));
    words.push(bytes.len() as u64);
    for chunk in bytes.chunks(8) {
        let mut limb = [0u8; 8];
        limb[..chunk.len()].copy_from_slice(chunk);
        words.push(u64::from_le_bytes(limb));
    }
    words
}

fn words_to_bytes(words: &[u64]) -> Option<Vec<u8>> {
    let (&byte_len_word, payload) = words.split_first()?;
    let byte_len = usize::try_from(byte_len_word).ok()?;
    if byte_len == 0 || byte_len > payload.len().checked_mul(8)? {
        return None;
    }
    let mut bytes = Vec::with_capacity(payload.len() * 8);
    for &word in payload {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    if bytes[byte_len..].iter().any(|&byte| byte != 0) {
        return None;
    }
    bytes.truncate(byte_len);
    Some(bytes)
}

fn proof_commitment(
    statement_binding: &[u64; DIGEST_WORDS],
    transcript_binding: &[u64; DIGEST_WORDS],
    provider_words: &[u64],
) -> [u64; DIGEST_WORDS] {
    let mut hasher = blake3::Hasher::new();
    update_words(
        &mut hasher,
        &[
            PROOF_COMMITMENT_DOMAIN,
            1,
            1,
            1,
            PVIA_SP1_PROOF_SYSTEM_ID as u64,
            provider_words.len() as u64,
        ],
    );
    update_words(&mut hasher, statement_binding);
    update_words(&mut hasher, transcript_binding);
    update_words(&mut hasher, provider_words);
    digest_from_bytes(hasher.finalize().as_bytes())
        .expect("blake3 digest length")
}

fn build_outer_artifact(
    statement_words: &[u64],
    proof: &SP1ProofWithPublicValues,
) -> Option<Vec<u64>> {
    if !PRODUCTION_PRIVACY_CONFIRMED {
        return None;
    }
    let statement_binding = statement_binding_from_words(statement_words)?;
    if !public_values_match_statement(proof, statement_words) {
        return None;
    }
    let transcript = transcript_binding(proof);
    if !digest_nonzero(&transcript) {
        return None;
    }
    let serialized = bincode::serialize(proof).ok()?;
    let provider_words = bytes_to_words(&serialized);
    if provider_words.is_empty() {
        return None;
    }
    let commitment =
        proof_commitment(&statement_binding, &transcript, &provider_words);

    let mut outer = vec![0u64; PROOF_HEADER_WORDS + provider_words.len()];
    outer[PROOF_AVAILABLE_INDEX] = 1;
    outer[PROOF_AUTHENTICATED_INDEX] = 1;
    outer[PROOF_ZERO_KNOWLEDGE_INDEX] = 1;
    outer[PROOF_SYSTEM_ID_INDEX] = PVIA_SP1_PROOF_SYSTEM_ID as u64;
    outer[PROOF_STATEMENT_BINDING_INDEX
        ..PROOF_STATEMENT_BINDING_INDEX + DIGEST_WORDS]
        .copy_from_slice(&statement_binding);
    outer[PROOF_TRANSCRIPT_BINDING_INDEX
        ..PROOF_TRANSCRIPT_BINDING_INDEX + DIGEST_WORDS]
        .copy_from_slice(&transcript);
    outer[PROOF_COMMITMENT_INDEX..PROOF_COMMITMENT_INDEX + DIGEST_WORDS]
        .copy_from_slice(&commitment);
    outer[PROOF_WORD_COUNT_INDEX] = provider_words.len() as u64;
    outer[PROOF_HEADER_WORDS..].copy_from_slice(&provider_words);
    Some(outer)
}
fn make_stdin(statement_words: &[u64], witness_words: &[u64]) -> SP1Stdin {
    let input = RelationInput {
        abi_version: ABI_VERSION,
        statement_words: statement_words.to_vec(),
        witness_words: witness_words.to_vec(),
    };
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);
    stdin
}

fn cpu_client() -> CpuProver {
    ProverClient::builder().cpu().build()
}

pub fn execute_relation(
    statement_words: &[u64],
    witness_words: &[u64],
) -> Result<RelationPublicValues, String> {
    if !validate_relation(statement_words, witness_words) {
        return Err("host relation validation failed".into());
    }
    let client = cpu_client();
    let (mut public_values, _) = client
        .execute(
            relation_elf(),
            make_stdin(statement_words, witness_words),
        )
        .calculate_gas(false)
        .run()
        .map_err(|e| format!("SP1 execute failed: {e}"))?;
    let actual = public_values.read::<RelationPublicValues>();
    let expected = expected_public_values(statement_words)
        .ok_or_else(|| "statement binding unavailable".to_string())?;
    if actual != expected {
        return Err("SP1 public values do not match the canonical statement".into());
    }
    Ok(actual)
}

pub fn prove_core_relation(
    statement_words: &[u64],
    witness_words: &[u64],
) -> Result<SP1ProofWithPublicValues, String> {
    if !validate_relation(statement_words, witness_words) {
        return Err("host relation validation failed".into());
    }
    let client = cpu_client();
    let pk = client
        .setup(relation_elf())
        .map_err(|e| format!("SP1 setup failed: {e}"))?;
    let proof = client
        .prove(
            &pk,
            make_stdin(statement_words, witness_words),
        )
        .core()
        .run()
        .map_err(|e| format!("SP1 Core prove failed: {e}"))?;
    client
        .verify(&proof, pk.verifying_key(), None)
        .map_err(|e| format!("SP1 verify failed: {e}"))?;
    if !public_values_match_statement(&proof, statement_words) {
        return Err("SP1 proof public values do not match the canonical statement".into());
    }
    Ok(proof)
}

pub fn prove_groth16_relation(
    statement_words: &[u64],
    witness_words: &[u64],
) -> Result<SP1ProofWithPublicValues, String> {
    if !validate_relation(statement_words, witness_words) {
        return Err("host relation validation failed".into());
    }
    let client = cpu_client();
    let pk = client
        .setup(relation_elf())
        .map_err(|e| format!("SP1 setup failed: {e}"))?;
    let proof = client
        .prove(
            &pk,
            make_stdin(statement_words, witness_words),
        )
        .groth16()
        .run()
        .map_err(|e| format!("SP1 Groth16 prove failed: {e}"))?;
    client
        .verify(&proof, pk.verifying_key(), None)
        .map_err(|e| format!("SP1 Groth16 verify failed: {e}"))?;
    if !public_values_match_statement(&proof, statement_words) {
        return Err("SP1 proof public values do not match the canonical statement".into());
    }
    Ok(proof)
}

pub fn prove_provider_relation(
    statement_words: &[u64],
    witness_words: &[u64],
) -> Result<SP1ProofWithPublicValues, String> {
    prove_groth16_relation(statement_words, witness_words)
}

pub fn provider_proof_mode_name() -> &'static str {
    PVIA_SP1_PROVIDER_PROOF_MODE
}

pub fn verify_sp1_relation_proof(
    statement_words: &[u64],
    proof: &SP1ProofWithPublicValues,
) -> Result<(), String> {
    if !public_values_match_statement(proof, statement_words) {
        return Err("SP1 proof public values do not match the canonical statement".into());
    }
    let client = cpu_client();
    let pk = client
        .setup(relation_elf())
        .map_err(|e| format!("SP1 setup failed: {e}"))?;
    client
        .verify(proof, pk.verifying_key(), None)
        .map_err(|e| format!("SP1 verify failed: {e}"))
}

fn parse_outer_artifact(
    statement_words: &[u64],
    outer: &[u64],
) -> Option<SP1ProofWithPublicValues> {
    if outer.len() < PROOF_HEADER_WORDS
        || outer[PROOF_AVAILABLE_INDEX] != 1
        || outer[PROOF_AUTHENTICATED_INDEX] != 1
        || outer[PROOF_ZERO_KNOWLEDGE_INDEX] != 1
        || outer[PROOF_SYSTEM_ID_INDEX] != PVIA_SP1_PROOF_SYSTEM_ID as u64
    {
        return None;
    }
    let statement_binding = statement_binding_from_words(statement_words)?;
    let stored_statement =
        &outer[PROOF_STATEMENT_BINDING_INDEX
            ..PROOF_STATEMENT_BINDING_INDEX + DIGEST_WORDS];
    if stored_statement != statement_binding {
        return None;
    }
    let stored_transcript =
        &outer[PROOF_TRANSCRIPT_BINDING_INDEX
            ..PROOF_TRANSCRIPT_BINDING_INDEX + DIGEST_WORDS];
    if !digest_nonzero(stored_transcript) {
        return None;
    }

    let provider_count = usize::try_from(outer[PROOF_WORD_COUNT_INDEX]).ok()?;
    if provider_count == 0
        || provider_count != outer.len().checked_sub(PROOF_HEADER_WORDS)?
    {
        return None;
    }
    let provider_words = &outer[PROOF_HEADER_WORDS..];
    let commitment =
        proof_commitment(&statement_binding, &stored_transcript.try_into().ok()?, provider_words);
    if outer[PROOF_COMMITMENT_INDEX
        ..PROOF_COMMITMENT_INDEX + DIGEST_WORDS] != commitment
    {
        return None;
    }

    let serialized = words_to_bytes(provider_words)?;
    let proof: SP1ProofWithPublicValues =
        bincode::deserialize(&serialized).ok()?;
    if !public_values_match_statement(&proof, statement_words) {
        return None;
    }
    let transcript = transcript_binding(&proof);
    if stored_transcript != transcript {
        return None;
    }
    Some(proof)
}

fn proof_request_key(
    statement_words: &[u64],
    witness_words: &[u64],
) -> [u64; DIGEST_WORDS] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PVIA_SP1_PROVIDER_REQUEST_V1");
    update_words(&mut hasher, &[statement_words.len() as u64]);
    update_words(&mut hasher, statement_words);
    update_words(&mut hasher, &[witness_words.len() as u64]);
    update_words(&mut hasher, witness_words);
    digest_from_bytes(hasher.finalize().as_bytes())
        .expect("blake3 digest length")
}

struct CachedArtifact {
    key: [u64; DIGEST_WORDS],
    words: Vec<u64>,
}

static PROOF_CACHE: std::sync::OnceLock<
    std::sync::Mutex<Option<CachedArtifact>>,
> = std::sync::OnceLock::new();

fn proof_cache() -> &'static std::sync::Mutex<Option<CachedArtifact>> {
    PROOF_CACHE.get_or_init(|| std::sync::Mutex::new(None))
}

unsafe fn input_words<'a>(ptr: *const u64, count: usize) -> Option<&'a [u64]> {
    if count == 0 || ptr.is_null() {
        return None;
    }
    Some(slice::from_raw_parts(ptr, count))
}

#[no_mangle]
pub extern "C" fn pvia_mc_provider_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
pub unsafe extern "C" fn pvia_mc_provider_capabilities(
    output_words: *mut u64,
    inout_word_count: *mut usize,
) -> i32 {
    if inout_word_count.is_null() {
        return 0;
    }
    let required = CAPABILITY_WORDS;
    if output_words.is_null() {
        *inout_word_count = required;
        return 1;
    }
    if *inout_word_count < required {
        *inout_word_count = required;
        return 0;
    }
    let words = capability_words();
    ptr::copy_nonoverlapping(words.as_ptr(), output_words, required);
    *inout_word_count = required;
    1
}

#[no_mangle]
pub unsafe extern "C" fn pvia_mc_provider_prove(
    statement_words_ptr: *const u64,
    statement_word_count: usize,
    witness_words_ptr: *const u64,
    witness_word_count: usize,
    proof_words: *mut u64,
    inout_proof_word_count: *mut usize,
) -> i32 {
    if inout_proof_word_count.is_null() || !PRODUCTION_PRIVACY_CONFIRMED {
        if !inout_proof_word_count.is_null() {
            *inout_proof_word_count = 0;
        }
        return 0;
    }
    let Some(statement_words) =
        input_words(statement_words_ptr, statement_word_count)
    else {
        *inout_proof_word_count = 0;
        return 0;
    };
    let Some(witness_words) =
        input_words(witness_words_ptr, witness_word_count)
    else {
        *inout_proof_word_count = 0;
        return 0;
    };
    if !validate_relation(statement_words, witness_words) {
        *inout_proof_word_count = 0;
        return 0;
    }

    let key = proof_request_key(statement_words, witness_words);
    let mut cache = match proof_cache().lock() {
        Ok(guard) => guard,
        Err(_) => {
            *inout_proof_word_count = 0;
            return 0;
        }
    };
    let needs_proof =
        cache.as_ref().map(|entry| entry.key != key).unwrap_or(true);
    if needs_proof {
        let proof = match prove_provider_relation(statement_words, witness_words) {
            Ok(value) => value,
            Err(_) => {
                *inout_proof_word_count = 0;
                return 0;
            }
        };
        let Some(words) = build_outer_artifact(statement_words, &proof) else {
            *inout_proof_word_count = 0;
            return 0;
        };
        *cache = Some(CachedArtifact { key, words });
    }

    let Some(entry) = cache.as_ref() else {
        *inout_proof_word_count = 0;
        return 0;
    };
    let required = entry.words.len();
    if proof_words.is_null() {
        *inout_proof_word_count = required;
        return 1;
    }
    if *inout_proof_word_count < required {
        *inout_proof_word_count = required;
        return 0;
    }
    ptr::copy_nonoverlapping(entry.words.as_ptr(), proof_words, required);
    *inout_proof_word_count = required;
    *cache = None;
    1
}

#[no_mangle]
pub unsafe extern "C" fn pvia_mc_provider_verify(
    statement_words_ptr: *const u64,
    statement_word_count: usize,
    proof_words_ptr: *const u64,
    proof_word_count: usize,
) -> i32 {
    if !PRODUCTION_PRIVACY_CONFIRMED {
        return 0;
    }
    let Some(statement_words) =
        input_words(statement_words_ptr, statement_word_count)
    else {
        return 0;
    };
    let Some(proof_words) =
        input_words(proof_words_ptr, proof_word_count)
    else {
        return 0;
    };
    let Some(proof) = parse_outer_artifact(statement_words, proof_words) else {
        return 0;
    };
    match verify_sp1_relation_proof(statement_words, &proof) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}
