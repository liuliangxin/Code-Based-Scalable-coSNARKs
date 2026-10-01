use pvia_mc_relation::{hash_words, relation_binding, validate_relation, FIELD_MODULUS};
use std::{collections::BTreeMap, env, fs, path::Path};

fn parse_hex_digest(text: &str) -> Result<[u64; 4], String> {
    if text.len() != 64 {
        return Err("digest hex length".into());
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| "digest hex")?;
    }
    let mut out = [0u64; 4];
    for i in 0..4 {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[8 * i..8 * i + 8]);
        out[i] = u64::from_le_bytes(limb);
    }
    Ok(out)
}

fn parse_words(text: &str) -> Result<Vec<u64>, String> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.split(',')
        .map(|x| x.parse::<u64>().map_err(|_| "word parse".to_string()))
        .collect()
}

fn check_file(path: &Path) -> Result<String, String> {
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut lines = content.lines();
    if lines.next() != Some("PVIA_MC_PROVIDER_RELATION_VECTOR_V1") {
        return Err(format!("{}: bad magic", path.display()));
    }
    let mut kv = BTreeMap::new();
    for line in lines {
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("{}: malformed line", path.display()));
        };
        kv.insert(k.to_string(), v.to_string());
    }
    let statement = parse_words(kv.get("statement_words").ok_or("statement_words")?)?;
    let witness = parse_words(kv.get("witness_words").ok_or("witness_words")?)?;
    let expected_relation =
        parse_hex_digest(kv.get("relation_binding").ok_or("relation_binding")?)?;
    let expected_statement_digest =
        parse_hex_digest(kv.get("statement_digest").ok_or("statement_digest")?)?;
    let expected_witness_digest =
        parse_hex_digest(kv.get("witness_digest").ok_or("witness_digest")?)?;

    if relation_binding() != expected_relation {
        return Err(format!("{}: relation binding mismatch", path.display()));
    }
    if hash_words(&statement) != expected_statement_digest {
        return Err(format!("{}: statement digest mismatch", path.display()));
    }
    if hash_words(&witness) != expected_witness_digest {
        return Err(format!("{}: witness digest mismatch", path.display()));
    }
    if !validate_relation(&statement, &witness) {
        return Err(format!("{}: relation validation failed", path.display()));
    }

    let mut changed_statement = statement.clone();
    changed_statement[2] = changed_statement[2].wrapping_add(1);
    if validate_relation(&changed_statement, &witness) {
        return Err(format!(
            "{}: changed statement was accepted", path.display()));
    }

    let mut changed_witness = witness.clone();
    changed_witness[6] = (changed_witness[6] + 1) % FIELD_MODULUS;
    if validate_relation(&statement, &changed_witness) {
        return Err(format!(
            "{}: changed witness product was accepted", path.display()));
    }

    Ok(kv.get("kind").cloned().unwrap_or_else(|| "unknown".into()))
}

fn main() {
    let dir = env::args().nth(1).expect("vectors directory argument");
    let mut files: Vec<_> = fs::read_dir(&dir)
        .expect("read vectors directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|x| x.to_str())
                .map(|x| x.starts_with("relation_") && x.ends_with(".txt"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no relation vectors");

    let mut vss = 0usize;
    let mut linear = 0usize;
    for path in &files {
        match check_file(path).unwrap_or_else(|e| panic!("{e}")).as_str() {
            "vss_local" => vss += 1,
            "linear" => linear += 1,
            _ => {}
        }
    }
    assert!(
        vss > 0 && linear > 0,
        "both relation vector kinds are required"
    );
    println!(
        "RUST_RELATION_VECTORS: PASS vectors={} vss_local={} linear={} consistency_checks=2_per_vector",
        files.len(),
        vss,
        linear
    );
}
