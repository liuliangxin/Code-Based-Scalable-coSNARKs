use serde::{Deserialize, Serialize};

pub const ABI_VERSION: u32 = 2;
pub const FIELD_MODULUS: u64 = 2_305_843_009_213_693_951;
pub const DIGEST_WORDS: usize = 4;

const STATEMENT_ABI_DOMAIN: u64 = 0x50564d4353544142;
const WITNESS_ABI_DOMAIN: u64 = 0x50564d4357544142;
const RELATION_BINDING_DOMAIN: u64 = 0x50564d4352454c42;
const RELATION_VERSION: u64 = 1;
const STATEMENT_BINDING_DOMAIN: u64 = 0x50564d554c435354;
const VSS_TRANSCRIPT_DOMAIN: u64 = 0x505656535354524e;
const VSS_DEALER_WITNESS_DOMAIN: u64 = 0x5056565353445754;
const VSS_LOCAL_WITNESS_DOMAIN: u64 = 0x50565653534c5754;
const VSS_WITNESS_VERSION: u64 = 1;
const LINEAR_BINDING_DOMAIN: u64 = 0x50564c494e424e44;
const LINEAR_WITNESS_DOMAIN: u64 = 0x50564c494e57544e;
const SHARING_WITNESS_DOMAIN: u64 = 0x50564d4353574954;
const SHARING_WITNESS_VERSION: u64 = 1;
const SHARING_KIND_VSS_LOCAL: u64 = 1;
const SHARING_KIND_LINEAR: u64 = 2;
const SHARING_KIND_VSS_DEALER: u64 = 3;
const STATEMENT_WORDS: usize = 26;
const WITNESS_HEADER_WORDS: usize = 11;
const SHARING_HEADER_WORDS: usize = 8;
const VSS_DEALER_FIXED_WORDS: usize = 18;
const VSS_LOCAL_FIXED_WORDS: usize = 23;
const LINEAR_FIXED_WORDS: usize = 8;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelationInput {
    pub abi_version: u32,
    pub statement_words: Vec<u64>,
    pub witness_words: Vec<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RelationPublicValues {
    pub abi_version: u32,
    pub relation_binding: [u64; DIGEST_WORDS],
    pub statement_binding: [u64; DIGEST_WORDS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FieldElement {
    real: u64,
    imaginary: u64,
}

#[derive(Clone, Copy)]
struct StatementView<'a> {
    sid: u64,
    checkpoint: u64,
    multiplication_id: u64,
    dealer: u64,
    lhs_binding: &'a [u64],
    rhs_binding: &'a [u64],
    output_binding: &'a [u64],
    context_binding: &'a [u64],
    statement_binding: &'a [u64],
}

#[derive(Clone, Copy)]
struct Envelope<'a> {
    kind: u64,
    binding: &'a [u64],
    payload: &'a [u64],
}

#[derive(Clone, Copy)]
struct WitnessView<'a> {
    lhs: FieldElement,
    rhs: FieldElement,
    product: FieldElement,
    lhs_section: &'a [u64],
    rhs_section: &'a [u64],
    output_section: &'a [u64],
}

#[derive(Clone, Copy)]
struct VssLocal<'a> {
    dealer: u64,
    participant: u64,
    world_size: u64,
    threshold: u64,
    element_count: u64,
    authenticated: u64,
    capability_binding: &'a [u64],
    local_row_commitment: &'a [u64],
    transcript_binding: &'a [u64],
    transport_words: &'a [u64],
    row_commitment_words: &'a [u64],
    local_row_words: &'a [u64],
}

#[derive(Clone, Copy)]
struct VssDealer<'a> {
    dealer: u64,
    world_size: u64,
    threshold: u64,
    element_count: u64,
    authenticated: u64,
    capability_binding: &'a [u64],
    transcript_binding: &'a [u64],
    transport_words: &'a [u64],
    row_commitment_words: &'a [u64],
    coefficient_words: &'a [u64],
}

#[derive(Clone, Copy)]
struct LinearView<'a> {
    local_share: FieldElement,
    source_count: u64,
    binding: &'a [u64],
    source_words: &'a [u64],
}

#[derive(Clone, Copy)]
struct LinearSource<'a> {
    sharing_binding: &'a [u64],
    coefficient_count: u64,
    coefficient_words: &'a [u64],
    local_vss_words: &'a [u64],
}

fn as_usize(value: u64) -> Option<usize> {
    usize::try_from(value).ok()
}

fn field_is_canonical(value: FieldElement) -> bool {
    value.real < FIELD_MODULUS && value.imaginary < FIELD_MODULUS
}

fn field_words_are_canonical(words: &[u64]) -> bool {
    words.len().is_multiple_of(2) && words.iter().all(|&w| w < FIELD_MODULUS)
}

fn fp_add(a: u64, b: u64) -> u64 {
    let sum = a + b;
    if sum >= FIELD_MODULUS {
        sum - FIELD_MODULUS
    } else {
        sum
    }
}

fn fp_sub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        FIELD_MODULUS - (b - a)
    }
}

fn fp_mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % FIELD_MODULUS as u128) as u64
}

fn field_add(lhs: FieldElement, rhs: FieldElement) -> FieldElement {
    FieldElement {
        real: fp_add(lhs.real, rhs.real),
        imaginary: fp_add(lhs.imaginary, rhs.imaginary),
    }
}

fn field_mul(lhs: FieldElement, rhs: FieldElement) -> FieldElement {
    let ac = fp_mul(lhs.real, rhs.real);
    let bd = fp_mul(lhs.imaginary, rhs.imaginary);
    let ad = fp_mul(lhs.real, rhs.imaginary);
    let bc = fp_mul(lhs.imaginary, rhs.real);
    FieldElement {
        real: fp_sub(ac, bd),
        imaginary: fp_add(ad, bc),
    }
}

fn update_words(hasher: &mut blake3::Hasher, words: &[u64]) {
    for &word in words {
        hasher.update(&word.to_le_bytes());
    }
}

pub fn hash_words(words: &[u64]) -> [u64; DIGEST_WORDS] {
    let mut hasher = blake3::Hasher::new();
    update_words(&mut hasher, words);
    digest_from_bytes(hasher.finalize().as_bytes())
}

fn digest_from_bytes(bytes: &[u8; 32]) -> [u64; DIGEST_WORDS] {
    let mut out = [0u64; DIGEST_WORDS];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        *slot = u64::from_le_bytes(limb);
    }
    out
}

fn digest_nonzero(words: &[u64]) -> bool {
    words.len() == DIGEST_WORDS && words.iter().any(|&w| w != 0)
}

fn digest_equal(lhs: &[u64], rhs: &[u64]) -> bool {
    lhs.len() == DIGEST_WORDS && rhs.len() == DIGEST_WORDS && lhs == rhs
}

pub fn relation_binding() -> [u64; DIGEST_WORDS] {
    let descriptor = [
        RELATION_BINDING_DOMAIN,
        RELATION_VERSION,
        ABI_VERSION as u64,
        FIELD_MODULUS,
        2,
        1,
        STATEMENT_BINDING_DOMAIN,
        STATEMENT_ABI_DOMAIN,
        STATEMENT_WORDS as u64,
        WITNESS_ABI_DOMAIN,
        WITNESS_HEADER_WORDS as u64,
        SHARING_WITNESS_DOMAIN,
        SHARING_WITNESS_VERSION,
        SHARING_KIND_VSS_LOCAL,
        SHARING_KIND_LINEAR,
        SHARING_KIND_VSS_DEALER,
        VSS_TRANSCRIPT_DOMAIN,
        VSS_DEALER_WITNESS_DOMAIN,
        VSS_LOCAL_WITNESS_DOMAIN,
        VSS_WITNESS_VERSION,
        VSS_DEALER_FIXED_WORDS as u64,
        VSS_LOCAL_FIXED_WORDS as u64,
        LINEAR_BINDING_DOMAIN,
        LINEAR_WITNESS_DOMAIN,
        LINEAR_FIXED_WORDS as u64,
    ];
    hash_words(&descriptor)
}

fn parse_statement(words: &[u64]) -> Option<StatementView<'_>> {
    if words.len() != STATEMENT_WORDS
        || words[0] != STATEMENT_ABI_DOMAIN
        || words[1] != ABI_VERSION as u64
        || words[2] == 0
        || words[3] == 0
        || words[4] == 0
        || words[5] > u32::MAX as u64
    {
        return None;
    }
    let view = StatementView {
        sid: words[2],
        checkpoint: words[3],
        multiplication_id: words[4],
        dealer: words[5],
        lhs_binding: &words[6..10],
        rhs_binding: &words[10..14],
        output_binding: &words[14..18],
        context_binding: &words[18..22],
        statement_binding: &words[22..26],
    };
    if digest_nonzero(view.lhs_binding)
        && digest_nonzero(view.rhs_binding)
        && digest_nonzero(view.output_binding)
        && digest_nonzero(view.context_binding)
        && digest_nonzero(view.statement_binding)
    {
        Some(view)
    } else {
        None
    }
}

fn parse_envelope(words: &[u64]) -> Option<Envelope<'_>> {
    if words.len() < SHARING_HEADER_WORDS
        || words[0] != SHARING_WITNESS_DOMAIN
        || words[1] != SHARING_WITNESS_VERSION
        || !(SHARING_KIND_VSS_LOCAL..=SHARING_KIND_VSS_DEALER).contains(&words[2])
    {
        return None;
    }
    let payload_n = as_usize(words[3])?;
    if payload_n == 0 || payload_n != words.len().checked_sub(SHARING_HEADER_WORDS)? {
        return None;
    }
    Some(Envelope {
        kind: words[2],
        binding: &words[4..8],
        payload: &words[8..],
    })
}

fn parse_witness(words: &[u64]) -> Option<WitnessView<'_>> {
    if words.len() < WITNESS_HEADER_WORDS
        || words[0] != WITNESS_ABI_DOMAIN
        || words[1] != ABI_VERSION as u64
    {
        return None;
    }
    let lhs = FieldElement {
        real: words[2],
        imaginary: words[3],
    };
    let rhs = FieldElement {
        real: words[4],
        imaginary: words[5],
    };
    let product = FieldElement {
        real: words[6],
        imaginary: words[7],
    };
    if !field_is_canonical(lhs) || !field_is_canonical(rhs) || !field_is_canonical(product) {
        return None;
    }
    let lhs_n = as_usize(words[8])?;
    let rhs_n = as_usize(words[9])?;
    let output_n = as_usize(words[10])?;
    let lhs_start = WITNESS_HEADER_WORDS;
    let rhs_start = lhs_start.checked_add(lhs_n)?;
    let output_start = rhs_start.checked_add(rhs_n)?;
    let end = output_start.checked_add(output_n)?;
    if end != words.len() {
        return None;
    }
    let lhs_section = &words[lhs_start..rhs_start];
    let rhs_section = &words[rhs_start..output_start];
    let output_section = &words[output_start..end];
    let lhs_env = parse_envelope(lhs_section)?;
    let rhs_env = parse_envelope(rhs_section)?;
    let out_env = parse_envelope(output_section)?;
    if !matches!(lhs_env.kind, SHARING_KIND_VSS_LOCAL | SHARING_KIND_LINEAR)
        || !matches!(rhs_env.kind, SHARING_KIND_VSS_LOCAL | SHARING_KIND_LINEAR)
        || out_env.kind != SHARING_KIND_VSS_DEALER
    {
        return None;
    }
    Some(WitnessView {
        lhs,
        rhs,
        product,
        lhs_section,
        rhs_section,
        output_section,
    })
}
fn parse_vss_local(words: &[u64]) -> Option<VssLocal<'_>> {
    if words.len() < VSS_LOCAL_FIXED_WORDS
        || words[0] != VSS_LOCAL_WITNESS_DOMAIN
        || words[1] != VSS_WITNESS_VERSION
        || words[7] > 1
    {
        return None;
    }
    let transport_n = as_usize(words[8])?;
    let row_n = as_usize(words[9])?;
    let row_word_n = as_usize(words[10])?;
    let world_size = words[4];
    if row_n != as_usize(world_size)? {
        return None;
    }
    let transport_words_n = transport_n.checked_mul(DIGEST_WORDS)?;
    let row_commitment_words_n = row_n.checked_mul(DIGEST_WORDS)?;
    let mut expected = VSS_LOCAL_FIXED_WORDS;
    expected = expected.checked_add(transport_words_n)?;
    expected = expected.checked_add(row_commitment_words_n)?;
    expected = expected.checked_add(row_word_n)?;
    if expected != words.len() {
        return None;
    }
    let dealer = words[2];
    let participant = words[3];
    let threshold = words[5];
    let element_count = words[6];
    if world_size < 2
        || dealer >= world_size
        || participant >= world_size
        || threshold >= world_size
        || element_count == 0
    {
        return None;
    }
    let mut offset = VSS_LOCAL_FIXED_WORDS;
    let transport_words = &words[offset..offset + transport_words_n];
    offset += transport_words_n;
    let row_commitment_words = &words[offset..offset + row_commitment_words_n];
    offset += row_commitment_words_n;
    let local_row_words = &words[offset..offset + row_word_n];
    if !field_words_are_canonical(local_row_words) {
        return None;
    }
    Some(VssLocal {
        dealer,
        participant,
        world_size,
        threshold,
        element_count,
        authenticated: words[7],
        capability_binding: &words[11..15],
        local_row_commitment: &words[15..19],
        transcript_binding: &words[19..23],
        transport_words,
        row_commitment_words,
        local_row_words,
    })
}

fn parse_vss_dealer(words: &[u64]) -> Option<VssDealer<'_>> {
    if words.len() < VSS_DEALER_FIXED_WORDS
        || words[0] != VSS_DEALER_WITNESS_DOMAIN
        || words[1] != VSS_WITNESS_VERSION
        || words[6] > 1
    {
        return None;
    }
    let transport_n = as_usize(words[7])?;
    let row_n = as_usize(words[8])?;
    let coefficient_n = as_usize(words[9])?;
    let world_size = words[3];
    if row_n != as_usize(world_size)? {
        return None;
    }
    let transport_words_n = transport_n.checked_mul(DIGEST_WORDS)?;
    let row_commitment_words_n = row_n.checked_mul(DIGEST_WORDS)?;
    let mut expected = VSS_DEALER_FIXED_WORDS;
    expected = expected.checked_add(transport_words_n)?;
    expected = expected.checked_add(row_commitment_words_n)?;
    expected = expected.checked_add(coefficient_n)?;
    if expected != words.len() {
        return None;
    }
    let dealer = words[2];
    let threshold = words[4];
    let element_count = words[5];
    if world_size < 2 || dealer >= world_size || threshold >= world_size || element_count == 0 {
        return None;
    }
    let mut offset = VSS_DEALER_FIXED_WORDS;
    let transport_words = &words[offset..offset + transport_words_n];
    offset += transport_words_n;
    let row_commitment_words = &words[offset..offset + row_commitment_words_n];
    offset += row_commitment_words_n;
    let coefficient_words = &words[offset..offset + coefficient_n];
    if !field_words_are_canonical(coefficient_words) {
        return None;
    }
    Some(VssDealer {
        dealer,
        world_size,
        threshold,
        element_count,
        authenticated: words[6],
        capability_binding: &words[10..14],
        transcript_binding: &words[14..18],
        transport_words,
        row_commitment_words,
        coefficient_words,
    })
}

fn parse_linear(words: &[u64]) -> Option<LinearView<'_>> {
    if words.len() < LINEAR_FIXED_WORDS || words[0] != LINEAR_WITNESS_DOMAIN || words[3] == 0 {
        return None;
    }
    let local_share = FieldElement {
        real: words[1],
        imaginary: words[2],
    };
    if !field_is_canonical(local_share) {
        return None;
    }
    Some(LinearView {
        local_share,
        source_count: words[3],
        binding: &words[4..8],
        source_words: &words[8..],
    })
}

fn linear_source_next<'a>(linear: &LinearView<'a>, offset: &mut usize) -> Option<LinearSource<'a>> {
    if *offset > linear.source_words.len() {
        return None;
    }
    let words = &linear.source_words[*offset..];
    if words.len() < 5 {
        return None;
    }
    let coefficient_count = as_usize(words[4])?;
    if coefficient_count == 0 {
        return None;
    }
    let coefficient_words_n = coefficient_count.checked_mul(2)?;
    if coefficient_words_n > words.len().checked_sub(5)? {
        return None;
    }
    let coefficient_words = &words[5..5 + coefficient_words_n];
    if !field_words_are_canonical(coefficient_words) {
        return None;
    }
    let mut pos = 5 + coefficient_words_n;
    if pos >= words.len() {
        return None;
    }
    let local_n = as_usize(words[pos])?;
    pos += 1;
    if local_n == 0 || local_n > words.len().checked_sub(pos)? {
        return None;
    }
    let local_vss_words = &words[pos..pos + local_n];
    parse_vss_local(local_vss_words)?;
    *offset = offset.checked_add(pos.checked_add(local_n)?)?;
    Some(LinearSource {
        sharing_binding: &words[0..4],
        coefficient_count: coefficient_count as u64,
        coefficient_words,
        local_vss_words,
    })
}

fn validate_sharing_payload(words: &[u64]) -> bool {
    let Some(envelope) = parse_envelope(words) else {
        return false;
    };
    match envelope.kind {
        SHARING_KIND_VSS_LOCAL => parse_vss_local(envelope.payload).is_some(),
        SHARING_KIND_VSS_DEALER => parse_vss_dealer(envelope.payload).is_some(),
        SHARING_KIND_LINEAR => {
            let Some(linear) = parse_linear(envelope.payload) else {
                return false;
            };
            let mut offset = 0usize;
            for _ in 0..linear.source_count {
                if linear_source_next(&linear, &mut offset).is_none() {
                    return false;
                }
            }
            offset == linear.source_words.len()
        }
        _ => false,
    }
}

fn validate_witness_payloads(witness: &WitnessView<'_>) -> bool {
    validate_sharing_payload(witness.lhs_section)
        && validate_sharing_payload(witness.rhs_section)
        && validate_sharing_payload(witness.output_section)
}

#[allow(clippy::too_many_arguments)]
fn vss_transcript_binding(
    dealer: u64,
    world_size: u64,
    threshold: u64,
    element_count: u64,
    authenticated: u64,
    capability_binding: &[u64],
    transport_words: &[u64],
    row_commitment_words: &[u64],
) -> Option<[u64; DIGEST_WORDS]> {
    if world_size < 2
        || dealer >= world_size
        || threshold >= world_size
        || element_count == 0
        || authenticated > 1
        || !transport_words.len().is_multiple_of(DIGEST_WORDS)
        || !row_commitment_words.len().is_multiple_of(DIGEST_WORDS)
    {
        return None;
    }
    let transport_count = transport_words.len() / DIGEST_WORDS;
    let row_count = row_commitment_words.len() / DIGEST_WORDS;
    if row_count != as_usize(world_size)? {
        return None;
    }
    for digest in row_commitment_words.chunks(DIGEST_WORDS) {
        if !digest_nonzero(digest) {
            return None;
        }
    }
    if authenticated == 1 {
        if !digest_nonzero(capability_binding) || transport_count == 0 {
            return None;
        }
        for digest in transport_words.chunks(DIGEST_WORDS) {
            if !digest_nonzero(digest) {
                return None;
            }
        }
    } else if digest_nonzero(capability_binding) || transport_count != 0 {
        return None;
    }

    let mut hasher = blake3::Hasher::new();
    update_words(
        &mut hasher,
        &[
            VSS_TRANSCRIPT_DOMAIN,
            dealer,
            world_size,
            threshold,
            element_count,
            authenticated,
            transport_count as u64,
        ],
    );
    if authenticated == 1 {
        update_words(&mut hasher, capability_binding);
        update_words(&mut hasher, transport_words);
    }
    update_words(&mut hasher, row_commitment_words);
    Some(digest_from_bytes(hasher.finalize().as_bytes()))
}

fn validate_vss_local(view: &VssLocal<'_>) -> bool {
    let Some(dimension) = as_usize(view.threshold).and_then(|v| v.checked_add(1)) else {
        return false;
    };
    let Some(element_count) = as_usize(view.element_count) else {
        return false;
    };
    let Some(expected_fields) = element_count.checked_mul(dimension) else {
        return false;
    };
    let Some(expected_words) = expected_fields.checked_mul(2) else {
        return false;
    };
    if view.local_row_words.len() != expected_words
        || !field_words_are_canonical(view.local_row_words)
    {
        return false;
    }
    let local_commitment = hash_words(view.local_row_words);
    if !digest_equal(&local_commitment, view.local_row_commitment) {
        return false;
    }
    let Some(participant) = as_usize(view.participant) else {
        return false;
    };
    let start = match participant.checked_mul(DIGEST_WORDS) {
        Some(v) => v,
        None => return false,
    };
    let end = match start.checked_add(DIGEST_WORDS) {
        Some(v) => v,
        None => return false,
    };
    if end > view.row_commitment_words.len()
        || !digest_equal(
            &view.row_commitment_words[start..end],
            view.local_row_commitment,
        )
    {
        return false;
    }
    let Some(transcript) = vss_transcript_binding(
        view.dealer,
        view.world_size,
        view.threshold,
        view.element_count,
        view.authenticated,
        view.capability_binding,
        view.transport_words,
        view.row_commitment_words,
    ) else {
        return false;
    };
    digest_equal(&transcript, view.transcript_binding)
}
fn validate_vss_dealer(view: &VssDealer<'_>) -> bool {
    let Some(dimension) = as_usize(view.threshold).and_then(|v| v.checked_add(1)) else {
        return false;
    };
    let Some(element_count) = as_usize(view.element_count) else {
        return false;
    };
    let Some(matrix_fields) = element_count
        .checked_mul(dimension)
        .and_then(|v| v.checked_mul(dimension))
    else {
        return false;
    };
    let Some(expected_words) = matrix_fields.checked_mul(2) else {
        return false;
    };
    if view.coefficient_words.len() != expected_words
        || !field_words_are_canonical(view.coefficient_words)
    {
        return false;
    }

    for k in 0..element_count {
        for a in 0..dimension {
            for b in 0..dimension {
                let lhs_field = (k * dimension + a) * dimension + b;
                let rhs_field = (k * dimension + b) * dimension + a;
                let lhs = FieldElement {
                    real: view.coefficient_words[2 * lhs_field],
                    imaginary: view.coefficient_words[2 * lhs_field + 1],
                };
                let rhs = FieldElement {
                    real: view.coefficient_words[2 * rhs_field],
                    imaginary: view.coefficient_words[2 * rhs_field + 1],
                };
                if lhs != rhs {
                    return false;
                }
            }
        }
    }

    let Some(fields_per_rank) = element_count.checked_mul(dimension) else {
        return false;
    };
    let Some(row_word_count) = fields_per_rank.checked_mul(2) else {
        return false;
    };
    let Some(world_size) = as_usize(view.world_size) else {
        return false;
    };
    if view.row_commitment_words.len() != world_size.saturating_mul(DIGEST_WORDS) {
        return false;
    }

    for participant in 0..world_size {
        let x = FieldElement {
            real: (participant + 1) as u64,
            imaginary: 0,
        };
        let mut row_words = vec![0u64; row_word_count];
        for k in 0..element_count {
            for b in 0..dimension {
                let mut value = FieldElement {
                    real: 0,
                    imaginary: 0,
                };
                let mut power = FieldElement {
                    real: 1,
                    imaginary: 0,
                };
                for a in 0..dimension {
                    let field_index = (k * dimension + a) * dimension + b;
                    let coefficient = FieldElement {
                        real: view.coefficient_words[2 * field_index],
                        imaginary: view.coefficient_words[2 * field_index + 1],
                    };
                    value = field_add(value, field_mul(coefficient, power));
                    power = field_mul(power, x);
                }
                let pos = 2 * (k * dimension + b);
                row_words[pos] = value.real;
                row_words[pos + 1] = value.imaginary;
            }
        }
        let digest = hash_words(&row_words);
        let start = participant * DIGEST_WORDS;
        if !digest_equal(
            &digest,
            &view.row_commitment_words[start..start + DIGEST_WORDS],
        ) {
            return false;
        }
    }

    let Some(transcript) = vss_transcript_binding(
        view.dealer,
        view.world_size,
        view.threshold,
        view.element_count,
        view.authenticated,
        view.capability_binding,
        view.transport_words,
        view.row_commitment_words,
    ) else {
        return false;
    };
    digest_equal(&transcript, view.transcript_binding)
}

fn validate_linear(linear: &LinearView<'_>, expected_participant: u64) -> Option<FieldElement> {
    if linear.source_count == 0 || !digest_nonzero(linear.binding) {
        return None;
    }
    let source_count = as_usize(linear.source_count)?;
    if source_count > linear.source_words.len() {
        return None;
    }

    let mut hasher = blake3::Hasher::new();
    update_words(&mut hasher, &[LINEAR_BINDING_DOMAIN, linear.source_count]);
    let mut total = FieldElement {
        real: 0,
        imaginary: 0,
    };
    let mut offset = 0usize;

    for _ in 0..source_count {
        let source = linear_source_next(linear, &mut offset)?;
        if !digest_nonzero(source.sharing_binding) || source.coefficient_count == 0 {
            return None;
        }
        let local = parse_vss_local(source.local_vss_words)?;
        if !validate_vss_local(&local)
            || local.participant != expected_participant
            || !digest_equal(local.transcript_binding, source.sharing_binding)
            || source.coefficient_count != local.element_count
        {
            return None;
        }

        update_words(&mut hasher, source.sharing_binding);
        update_words(&mut hasher, &[source.coefficient_count]);
        update_words(&mut hasher, source.coefficient_words);

        let dimension = as_usize(local.threshold)?.checked_add(1)?;
        let coefficient_count = as_usize(source.coefficient_count)?;
        let mut source_value = FieldElement {
            real: 0,
            imaginary: 0,
        };
        for j in 0..coefficient_count {
            let local_word_index = 2usize.checked_mul(j.checked_mul(dimension)?)?;
            if local_word_index + 1 >= local.local_row_words.len() {
                return None;
            }
            let coefficient = FieldElement {
                real: source.coefficient_words[2 * j],
                imaginary: source.coefficient_words[2 * j + 1],
            };
            let local_element = FieldElement {
                real: local.local_row_words[local_word_index],
                imaginary: local.local_row_words[local_word_index + 1],
            };
            source_value = field_add(source_value, field_mul(coefficient, local_element));
        }
        total = field_add(total, source_value);
    }

    if offset != linear.source_words.len() {
        return None;
    }
    let binding = digest_from_bytes(hasher.finalize().as_bytes());
    if !digest_equal(&binding, linear.binding) || total != linear.local_share {
        return None;
    }
    Some(total)
}

fn statement_binding(view: &StatementView<'_>) -> [u64; DIGEST_WORDS] {
    let mut hasher = blake3::Hasher::new();
    update_words(
        &mut hasher,
        &[
            STATEMENT_BINDING_DOMAIN,
            view.sid,
            view.checkpoint,
            view.multiplication_id,
            view.dealer,
        ],
    );
    update_words(&mut hasher, view.lhs_binding);
    update_words(&mut hasher, view.rhs_binding);
    update_words(&mut hasher, view.output_binding);
    update_words(&mut hasher, view.context_binding);
    digest_from_bytes(hasher.finalize().as_bytes())
}

fn input_share(
    section: &[u64],
    expected_participant: u64,
    expected_binding: &[u64],
) -> Option<FieldElement> {
    let envelope = parse_envelope(section)?;
    if !digest_equal(envelope.binding, expected_binding) {
        return None;
    }
    match envelope.kind {
        SHARING_KIND_VSS_LOCAL => {
            let local = parse_vss_local(envelope.payload)?;
            if !validate_vss_local(&local)
                || local.participant != expected_participant
                || local.element_count != 1
                || !digest_equal(local.transcript_binding, expected_binding)
                || local.local_row_words.len() < 2
            {
                return None;
            }
            Some(FieldElement {
                real: local.local_row_words[0],
                imaginary: local.local_row_words[1],
            })
        }
        SHARING_KIND_LINEAR => {
            let linear = parse_linear(envelope.payload)?;
            if !digest_equal(linear.binding, expected_binding) {
                return None;
            }
            validate_linear(&linear, expected_participant)
        }
        _ => None,
    }
}

fn output_value(
    section: &[u64],
    expected_dealer: u64,
    expected_binding: &[u64],
) -> Option<FieldElement> {
    let envelope = parse_envelope(section)?;
    if envelope.kind != SHARING_KIND_VSS_DEALER || !digest_equal(envelope.binding, expected_binding)
    {
        return None;
    }
    let dealer = parse_vss_dealer(envelope.payload)?;
    if !validate_vss_dealer(&dealer)
        || dealer.dealer != expected_dealer
        || dealer.element_count != 1
        || !digest_equal(dealer.transcript_binding, expected_binding)
        || dealer.coefficient_words.len() < 2
    {
        return None;
    }
    Some(FieldElement {
        real: dealer.coefficient_words[0],
        imaginary: dealer.coefficient_words[1],
    })
}

pub fn statement_binding_from_words(statement_words: &[u64]) -> Option<[u64; DIGEST_WORDS]> {
    let statement = parse_statement(statement_words)?;
    let binding = statement_binding(&statement);
    if digest_equal(&binding, statement.statement_binding) {
        Some(binding)
    } else {
        None
    }
}

pub fn validate_relation(statement_words: &[u64], witness_words: &[u64]) -> bool {
    let Some(statement) = parse_statement(statement_words) else {
        return false;
    };
    let binding = statement_binding(&statement);
    if !digest_equal(&binding, statement.statement_binding) {
        return false;
    }
    let Some(witness) = parse_witness(witness_words) else {
        return false;
    };
    if !validate_witness_payloads(&witness) {
        return false;
    }
    let product = field_mul(witness.lhs, witness.rhs);
    if product != witness.product {
        return false;
    }

    let Some(lhs) = input_share(witness.lhs_section, statement.dealer, statement.lhs_binding)
    else {
        return false;
    };
    let Some(rhs) = input_share(witness.rhs_section, statement.dealer, statement.rhs_binding)
    else {
        return false;
    };
    let Some(output) = output_value(
        witness.output_section,
        statement.dealer,
        statement.output_binding,
    ) else {
        return false;
    };

    lhs == witness.lhs
        && rhs == witness.rhs
        && output == witness.product
        && output == field_mul(lhs, rhs)
}

pub fn evaluate(input: &RelationInput) -> Option<RelationPublicValues> {
    if input.abi_version != ABI_VERSION
        || !validate_relation(&input.statement_words, &input.witness_words)
    {
        return None;
    }
    Some(RelationPublicValues {
        abi_version: ABI_VERSION,
        relation_binding: relation_binding(),
        statement_binding: statement_binding_from_words(&input.statement_words)?,
    })
}
