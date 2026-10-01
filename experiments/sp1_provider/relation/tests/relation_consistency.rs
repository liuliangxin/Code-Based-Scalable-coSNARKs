use pvia_mc_relation::validate_relation;
use std::{collections::BTreeMap, fs, path::Path};

fn parse_words(text: &str) -> Vec<u64> {
    text.split(',')
        .filter(|x| !x.is_empty())
        .map(|x| x.parse::<u64>().expect("word"))
        .collect()
}

fn load_vector(path: &Path) -> (Vec<u64>, Vec<u64>) {
    let text = fs::read_to_string(path).expect("read vector");
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("PVIA_MC_PROVIDER_RELATION_VECTOR_V1"));
    let mut kv = BTreeMap::new();
    for line in lines {
        let (k, v) = line.split_once('=').expect("key/value");
        kv.insert(k.to_string(), v.to_string());
    }
    (
        parse_words(kv.get("statement_words").unwrap()),
        parse_words(kv.get("witness_words").unwrap()),
    )
}

#[test]
fn canonical_vector_accepts_and_changed_inputs_reject() {
    let path = std::env::var("PVIA_MC_TEST_VECTOR").expect("PVIA_MC_TEST_VECTOR");
    let (statement, witness) = load_vector(Path::new(&path));
    assert!(validate_relation(&statement, &witness));

    let mut changed_statement = statement.clone();
    changed_statement[2] ^= 1;
    assert!(!validate_relation(&changed_statement, &witness));

    let mut changed_witness = witness.clone();
    changed_witness[2] = (changed_witness[2] + 1) % 2_305_843_009_213_693_951u64;
    assert!(!validate_relation(&statement, &changed_witness));
}
