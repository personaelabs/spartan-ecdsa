#![allow(non_snake_case)]
use bincode;
use circuit_reader::load_as_spartan_inst;
use std::env::{args, current_dir};
use std::fs::File;
use std::io::Write;

fn main() {
    let circom_r1cs_path = args().nth(1).unwrap();
    let output_path = args().nth(2).unwrap();
    let num_pub_inputs = args().nth(3).unwrap().parse::<usize>().unwrap();

    let root = current_dir().unwrap();
    let circom_r1cs_path = root.join(circom_r1cs_path);
    let spartan_inst = load_as_spartan_inst(circom_r1cs_path, num_pub_inputs);
    let sparta_inst_bytes = bincode::serialize(&spartan_inst).unwrap();

    File::create(root.join(output_path.clone()))
        .unwrap()
        .write_all(sparta_inst_bytes.as_slice())
        .unwrap();

    println!("Written Spartan circuit to {}", output_path);
}
