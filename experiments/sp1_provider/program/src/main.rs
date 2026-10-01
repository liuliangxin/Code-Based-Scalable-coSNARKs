#![no_main]
sp1_zkvm::entrypoint!(main);

use pvia_mc_relation::{evaluate, RelationInput};

pub fn main() {
    let input = sp1_zkvm::io::read::<RelationInput>();
    let public_values = evaluate(&input).expect("invalid multiplication-consistency relation");
    sp1_zkvm::io::commit(&public_values);
}
