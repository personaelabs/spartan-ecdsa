// !Not working yet!
use crate::circuits::utils::convert_to_spartan_r1cs;
use libsecp256k1::{sign, Message, SecretKey};
use libspartan::{Assignment, NIZKGens, NIZK};
use merlin::Transcript;
use nova_scotia::circom::reader::load_r1cs;
use num_bigint::BigUint;
use serde_json::json;
use std::env::current_dir;
use std::{collections::HashMap, str::FromStr};

use super::utils::generate_witness;

pub fn ecdsa_membership() {
    let message = Message::parse_slice(&[1u8; 32]).unwrap();
    let secret_key = SecretKey::parse_slice(&[1u8; 32]).unwrap();
    let (sig, v) = sign(&message, &secret_key);

    let p = BigUint::from_str(
        "115792089237316195423570985008687907853269984665640564039457584007908834671663",
    )
    .unwrap();

    let s = BigUint::from_bytes_be(&sig.s.b32());
    let msg = BigUint::from_bytes_be(&message.serialize());
    let r_x = BigUint::from_bytes_be(&sig.r.b32());
    let r_x_squared = r_x.modpow(&BigUint::from(1u32), &p);
    let r_inv = BigUint::from_bytes_be(&sig.r.inv().b32()).modpow(&BigUint::from(1u32), &p);

    let r_y = (r_x.modpow(&BigUint::from(3u32), &p) + BigUint::from(7u32))
        .sqrt()
        .modpow(&BigUint::from(1u32), &p);

    let r_y_squared = r_y.pow(2u32);

    // specify the size of an R1CS instance
    let num_vars = 3536;
    let num_cons = 2509;
    let num_inputs = 0;
    let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

    let root = current_dir().unwrap();

    let mut private_input = HashMap::new();
    private_input.insert("s".to_string(), json!(s.to_str_radix(10)));
    private_input.insert("msg".to_string(), json!(msg.to_str_radix(10)));
    private_input.insert("rInv".to_string(), json!(r_inv.to_str_radix(10)));
    private_input.insert("rX".to_string(), json!(r_x.to_str_radix(10)));
    private_input.insert("rXSquared".to_string(), json!(r_x_squared.to_str_radix(10)));
    private_input.insert("rY".to_string(), json!(r_y.to_str_radix(10)));
    private_input.insert("rYSquared".to_string(), json!(r_y_squared.to_str_radix(10)));
    private_input.insert("pathIndices".to_string(), json!([1, 1, 1]));
    private_input.insert("siblings".to_string(), json!([1, 1, 1]));

    let circuit_file = root.join("circuits/membership.r1cs");
    let r1cs = load_r1cs(&circuit_file);

    let public_input = Assignment::new(&[]).unwrap();
    let spartan_inst = convert_to_spartan_r1cs(&r1cs, num_vars, 0);

    let witness_generator_file = root.join("circuits/membership_js/membership.wasm");

    let assignment = generate_witness(witness_generator_file, private_input);

    let mut prover_transcript = Transcript::new(b"example");

    let proof = NIZK::prove(
        &spartan_inst,
        assignment,
        &public_input,
        &gens,
        &mut prover_transcript,
    );

    let mut verifier_transcript = Transcript::new(b"example");

    proof
        .verify(
            &spartan_inst,
            &public_input,
            &mut verifier_transcript,
            &gens,
        )
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_membership() {
        ecdsa_membership();
    }
}
