use ff::PrimeField;
use libspartan::{Assignment, Instance};
use nova_scotia::circom::circuit::R1CS;
use serde_json::Value;
use std::{collections::HashMap, env::current_dir, fs, path::PathBuf};

use nova_scotia::{circom::reader::generate_witness_from_wasm, F1};

pub fn convert_to_spartan_r1cs<F: PrimeField<Repr = [u8; 32]>>(
    r1cs: &R1CS<F>,
    num_vars: usize,
    num_pub_inputs: usize,
) -> Instance {
    //    let num_vars = r1cs.num_variables;
    let num_cons = r1cs.constraints.len();
    let num_inputs = num_pub_inputs;
    let mut A = vec![];
    let mut B = vec![];
    let mut C = vec![];

    for (i, constraint) in r1cs.constraints.iter().enumerate() {
        let (a, b, c) = constraint;

        for (j, coeff) in a.iter() {
            let bytes: [u8; 32] = coeff.to_repr();

            A.push((*j, i, bytes));
        }

        for (j, coeff) in b.iter() {
            let bytes: [u8; 32] = coeff.to_repr();
            B.push((*j, i, bytes));
        }

        for (j, coeff) in c.iter() {
            let bytes: [u8; 32] = coeff.to_repr();
            C.push((*j, i, bytes));
        }
    }

    let inst = Instance::new(
        num_vars,
        num_cons,
        num_inputs,
        A.as_slice(),
        B.as_slice(),
        C.as_slice(),
    )
    .unwrap();

    inst
}

pub fn generate_witness(
    witness_generator_file: PathBuf,
    private_input: HashMap<String, Value>,
) -> Assignment {
    let root = current_dir().unwrap();
    let witness_generator_input = root.join("circom_input.json");
    let witness_generator_output = root.join("circom_witness.wtns");

    let input_json = serde_json::to_string(&private_input).unwrap();
    fs::write(&witness_generator_input, input_json).unwrap();

    // Init empty wtns file
    fs::write(&witness_generator_output, "").unwrap();

    let witness = generate_witness_from_wasm::<F1>(
        &witness_generator_file,
        &witness_generator_input,
        &witness_generator_output,
    );

    let witness_bytes = witness
        .iter()
        .map(|w| w.to_repr())
        .collect::<Vec<[u8; 32]>>();

    Assignment::new(witness_bytes.as_slice()).unwrap()
}
