#![allow(non_snake_case)]
use bincode;
use ff::PrimeField;
use libspartan::Instance;
use secq256k1::AffinePoint;
use secq256k1::FieldBytes;
use spartan_wasm::circom_reader::{load_r1cs_from_bin_file, R1CS};
use std::env::{args, current_dir};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let circuit_path = args().nth(1).unwrap();
    let output_path = args().nth(2).unwrap();
    let num_pub_inputs = args().nth(3).unwrap().parse::<usize>().unwrap();

    let root = current_dir().unwrap();
    let circuit_path = root.join(circuit_path);
    let spartan_inst = load_as_spartan_inst(circuit_path, num_pub_inputs);
    let sparta_inst_bytes = bincode::serialize(&spartan_inst).unwrap();

    File::create(root.join(output_path.clone()))
        .unwrap()
        .write_all(sparta_inst_bytes.as_slice())
        .unwrap();

    println!("Written Spartan circuit to {}", output_path);
}

pub fn load_as_spartan_inst(circuit_file: PathBuf, num_pub_inputs: usize) -> Instance {
    let root = current_dir().unwrap();

    let circuit_file = root.join(circuit_file);
    let (r1cs, _) = load_r1cs_from_bin_file::<AffinePoint>(&circuit_file);

    let spartan_inst = convert_to_spartan_r1cs(&r1cs, num_pub_inputs);

    spartan_inst
}

fn convert_to_spartan_r1cs<F: PrimeField<Repr = FieldBytes>>(
    r1cs: &R1CS<F>,
    num_pub_inputs: usize,
) -> Instance {
    let num_cons = r1cs.constraints.len();
    let num_vars = r1cs.num_variables;
    let num_inputs = num_pub_inputs;

    let mut A = vec![];
    let mut B = vec![];
    let mut C = vec![];

    for (i, constraint) in r1cs.constraints.iter().enumerate() {
        let (a, b, c) = constraint;

        for (j, coeff) in a.iter() {
            let bytes: [u8; 32] = coeff.to_repr().into();

            A.push((i, *j, bytes));
        }

        for (j, coeff) in b.iter() {
            let bytes: [u8; 32] = coeff.to_repr().into();
            B.push((i, *j, bytes));
        }

        for (j, coeff) in c.iter() {
            let bytes: [u8; 32] = coeff.to_repr().into();
            C.push((i, *j, bytes));
        }
    }

    let inst = Instance::new(
        num_cons,
        num_vars,
        num_inputs,
        A.as_slice(),
        B.as_slice(),
        C.as_slice(),
    )
    .unwrap();

    inst
}
