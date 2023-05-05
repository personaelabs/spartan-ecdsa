use crate::k256_consts::*;
use crate::{Poseidon, PoseidonConstants};
pub use secq256k1::field::field_secp::FieldElement;

#[allow(dead_code)]
pub fn hash(input: &[FieldElement; 2]) -> FieldElement {
    let constants = PoseidonConstants::<FieldElement>::new(
        ROUND_CONSTANTS.to_vec(),
        vec![
            MDS_MATRIX[0].to_vec(),
            MDS_MATRIX[1].to_vec(),
            MDS_MATRIX[2].to_vec(),
        ],
        NUM_FULL_ROUNDS,
        NUM_PARTIAL_ROUNDS,
    );
    let mut poseidon = Poseidon::new(constants);

    let result = poseidon.hash(input);

    result
}
