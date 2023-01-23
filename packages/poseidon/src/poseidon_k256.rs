use crate::{k256_consts, Poseidon, PoseidonConstants};
use ff::PrimeField;
pub use secq256k1::field::field_secp::FieldElement;

#[allow(dead_code)]
pub fn hash(input: Vec<FieldElement>) -> FieldElement {
    let round_constants: Vec<FieldElement> = k256_consts::ROUND_CONSTANTS
        .iter()
        .map(|x| FieldElement::from_str_vartime(x).unwrap())
        .collect();

    let mds_matrix: Vec<Vec<FieldElement>> = k256_consts::MDS_MATRIX
        .iter()
        .map(|x| {
            x.iter()
                .map(|y| FieldElement::from_str_vartime(y).unwrap())
                .collect::<Vec<FieldElement>>()
        })
        .collect();

    let constants = PoseidonConstants::<FieldElement>::new(
        round_constants,
        mds_matrix,
        k256_consts::NUM_FULL_ROUNDS,
        k256_consts::NUM_PARTIAL_ROUNDS,
    );
    let mut poseidon = Poseidon::new(constants);

    let result = poseidon.hash(input);

    result
}
