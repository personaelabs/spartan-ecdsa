use bincode;
use spartan_wasm::circuits::utils::load_as_spartan_inst;
use std::env::{args, current_dir};
use std::fs::File;
use std::io::Write;

fn main() {
    let circuit_path = args().nth(1).unwrap();
    let output_path = args().nth(2).unwrap();

    let root = current_dir().unwrap();
    let circuit_path = root.join(circuit_path);
    let spartan_inst = load_as_spartan_inst(circuit_path, 0);
    let sparta_inst_bytes = bincode::serialize(&spartan_inst).unwrap();

    File::create(root.join(output_path.clone()))
        .unwrap()
        .write_all(sparta_inst_bytes.as_slice())
        .unwrap();

    println!("Written Spartan circuit to {}", output_path);
}
